package controllers

import (
	"context"
	"fmt"
	"path"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	msiacrpullv1beta2 "github.com/Azure/msi-acrpull/api/v1beta2"
	"github.com/Azure/msi-acrpull/pkg/authorizer"
	"github.com/Azure/msi-acrpull/pkg/authorizer/types"
)

const (
	ownerKey                  = ".metadata.controller"
	dockerConfigKey           = ".dockerconfigjson"
	msiAcrPullFinalizerName   = "msi-acrpull.microsoft.com"
	defaultServiceAccountName = "default"

	tokenRefreshBuffer = time.Minute * 30
)

// AcrPullBindingReconciler reconciles a AcrPullBinding object
type AcrPullBindingReconciler struct {
	client.Client
	Log                              logr.Logger
	Scheme                           *runtime.Scheme
	Auth                             authorizer.Interface
	DefaultManagedIdentityResourceID string
	DefaultManagedIdentityClientID   string
	DefaultACRServer                 string
}

// +kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=*
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;update;patch

func (r *AcrPullBindingReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("acrpullbinding", req.NamespacedName)

	var acrBinding msiacrpullv1beta2.AcrPullBinding
	if err := r.Get(ctx, req.NamespacedName, &acrBinding); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "unable to fetch acrPullBinding.")
			return ctrl.Result{}, err
		}
		log.Info("AcrPullBinding is not found. Ignore because this is expected to happen when it is being deleted.")
		return ctrl.Result{}, nil
	}

	serviceAccountName := getServiceAccountName(acrBinding.Spec.ServiceAccountName)

	// examine DeletionTimestamp to determine if acr pull binding is under deletion
	if acrBinding.ObjectMeta.DeletionTimestamp.IsZero() {
		// the object is not being deleted, so if it does not have our finalizer,
		// then need to add the finalizer and update the object.
		if err := r.addFinalizer(ctx, &acrBinding, log); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		// the object is being deleted
		if err := r.removeFinalizer(ctx, &acrBinding, req, serviceAccountName, log); err != nil {
			return ctrl.Result{}, err
		}

		// stop reconciliation as the item is being deleted
		return ctrl.Result{}, nil
	}

	acrServer := getACRServer(r, acrBinding.Spec)
	var acrAccessToken types.AccessToken
	var err error

	if acrBinding.Spec.WorkloadIdentityClientID != "" {
		clientID := acrBinding.Spec.WorkloadIdentityClientID
		tenantID := acrBinding.Spec.WorkloadIdentityTenantID
		acrAccessToken, err = r.Auth.AcquireACRAccessTokenWithWorkloadIdentity(ctx, clientID, tenantID, acrServer)
	} else {
		msiClientID, msiResourceID := specOrDefault(r, acrBinding.Spec)
		acrAccessToken, err = r.Auth.AcquireACRAccessTokenWithManagedIdentity(msiClientID, msiResourceID, acrServer)
	}
	if err != nil {
		log.Error(err, "Failed to get ACR access token")
		if err := r.setErrStatus(ctx, err, &acrBinding); err != nil {
			log.Error(err, "Failed to update error status")
		}

		return ctrl.Result{}, err
	}

	dockerConfig := authorizer.CreateACRDockerCfg(acrServer, acrAccessToken)

	var pullSecrets v1.SecretList
	if err := r.List(ctx, &pullSecrets, client.InNamespace(req.Namespace), client.MatchingFields{ownerKey: req.Name}); err != nil {
		log.Error(err, "unable to list child secrets")
		return ctrl.Result{}, err
	}
	pullSecret := getPullSecret(&acrBinding, pullSecrets.Items)

	// Create a new secret if one doesn't already exist
	if pullSecret == nil {
		log.Info("Creating new pull secret")

		pullSecret, err := newBasePullSecret(&acrBinding, dockerConfig, r.Scheme)
		if err != nil {
			log.Error(err, "Failed to construct pull secret")
			return ctrl.Result{}, err
		}

		if err := r.Create(ctx, pullSecret); err != nil {
			log.Error(err, "Failed to create pull secret in cluster")
			return ctrl.Result{}, err
		}
	} else {
		log.Info("Updating existing pull secret")

		pullSecret := updatePullSecret(&pullSecrets.Items[0], dockerConfig)
		if err := r.Update(ctx, pullSecret); err != nil {
			log.Error(err, "Failed to update pull secret")
			return ctrl.Result{}, err
		}
	}

	// Associate the image pull secret with the default service account of the namespace
	if err := r.updateServiceAccount(ctx, &acrBinding, req, serviceAccountName, log); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.setSuccessStatus(ctx, &acrBinding, acrAccessToken); err != nil {
		log.Error(err, "Failed to update acr binding status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{
		RequeueAfter: getTokenRefreshDuration(acrAccessToken),
	}, nil
}

func specOrDefault(r *AcrPullBindingReconciler, spec msiacrpullv1beta2.AcrPullBindingSpec) (string, string) {
	msiClientID := spec.ManagedIdentityClientID
	msiResourceID := path.Clean(spec.ManagedIdentityResourceID)
	if msiClientID == "" {
		msiClientID = r.DefaultManagedIdentityClientID
	}
	if msiResourceID == "." {
		msiResourceID = r.DefaultManagedIdentityResourceID
	}

	return msiClientID, msiResourceID
}

func getACRServer(r *AcrPullBindingReconciler, spec msiacrpullv1beta2.AcrPullBindingSpec) string {
	acrServer := spec.AcrServer
	if acrServer == "" {
		acrServer = r.DefaultACRServer
	}

	return acrServer
}

func (r *AcrPullBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(&v1.Secret{}, ownerKey, func(rawObj runtime.Object) []string {
		secret := rawObj.(*v1.Secret)
		owner := metav1.GetControllerOf(secret)
		if owner == nil {
			return nil
		}

		if owner.APIVersion != msiacrpullv1beta2.GroupVersion.String() || owner.Kind != "AcrPullBinding" {
			return nil
		}

		return []string{owner.Name}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&msiacrpullv1beta2.AcrPullBinding{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}). // Needed to not enter reconcile loop on status update
		Owns(&v1.Secret{}).
		Complete(r)
}

func (r *AcrPullBindingReconciler) addFinalizer(ctx context.Context, acrBinding *msiacrpullv1beta2.AcrPullBinding, log logr.Logger) error {
	if !containsString(acrBinding.ObjectMeta.Finalizers, msiAcrPullFinalizerName) {
		acrBinding.ObjectMeta.Finalizers = append(acrBinding.ObjectMeta.Finalizers, msiAcrPullFinalizerName)
		if err := r.Update(ctx, acrBinding); err != nil {
			log.Error(err, "Failed to append acr pull binding finalizer", "finalizerName", msiAcrPullFinalizerName)
			return err
		}
	}
	return nil
}

func (r *AcrPullBindingReconciler) removeFinalizer(ctx context.Context, acrBinding *msiacrpullv1beta2.AcrPullBinding,
	req ctrl.Request, serviceAccountName string, log logr.Logger) error {
	if containsString(acrBinding.ObjectMeta.Finalizers, msiAcrPullFinalizerName) {
		// our finalizer is present, so need to clean up ImagePullSecret reference
		var serviceAccount v1.ServiceAccount
		saNamespacedName := k8stypes.NamespacedName{
			Namespace: req.Namespace,
			Name:      serviceAccountName,
		}
		if err := r.Get(ctx, saNamespacedName, &serviceAccount); err != nil {
			if !apierrors.IsNotFound(err) {
				log.Error(err, "Failed to get service account")
				return err
			}
			log.Info("Service account is not found. Continue removing finalizer", "serviceAccountName", saNamespacedName.Name)
		} else {
			pullSecretName := getPullSecretName(acrBinding.Name)
			serviceAccount.ImagePullSecrets = removeImagePullSecretRef(serviceAccount.ImagePullSecrets, pullSecretName)
			if err := r.Update(ctx, &serviceAccount); err != nil {
				log.Error(err, "Failed to remove image pull secret reference from default service account", "pullSecretName", pullSecretName)
				return err
			}
		}

		// remove our finalizer from the list and update it.
		acrBinding.ObjectMeta.Finalizers = removeString(acrBinding.ObjectMeta.Finalizers, msiAcrPullFinalizerName)
		if err := r.Update(ctx, acrBinding); err != nil {
			log.Error(err, "Failed to remove acr pull binding finalizer", "finalizerName", msiAcrPullFinalizerName)
			return err
		}
	}
	return nil
}

func (r *AcrPullBindingReconciler) updateServiceAccount(ctx context.Context, acrBinding *msiacrpullv1beta2.AcrPullBinding,
	req ctrl.Request, serviceAccountName string, log logr.Logger) error {
	var serviceAccount v1.ServiceAccount
	saNamespacedName := k8stypes.NamespacedName{
		Namespace: req.Namespace,
		Name:      serviceAccountName,
	}
	if err := r.Get(ctx, saNamespacedName, &serviceAccount); err != nil {
		log.Error(err, "Failed to get service account")
		return err
	}
	pullSecretName := getPullSecretName(acrBinding.Name)
	if !imagePullSecretRefExist(serviceAccount.ImagePullSecrets, pullSecretName) {
		log.Info("Updating default service account")
		appendImagePullSecretRef(&serviceAccount, pullSecretName)
		if err := r.Update(ctx, &serviceAccount); err != nil {
			log.Error(err, "Failed to append image pull secret reference to default service account", "pullSecretName", pullSecretName)
			return err
		}
	}
	return nil
}

func (r *AcrPullBindingReconciler) setSuccessStatus(ctx context.Context, acrBinding *msiacrpullv1beta2.AcrPullBinding, accessToken types.AccessToken) error {
	tokenExp, err := accessToken.GetTokenExp()
	if err != nil {
		return err
	}

	acrBinding.Status = msiacrpullv1beta2.AcrPullBindingStatus{
		TokenExpirationTime:  &metav1.Time{Time: tokenExp},
		LastTokenRefreshTime: &metav1.Time{Time: time.Now().UTC()},
	}

	if err := r.Status().Update(ctx, acrBinding); err != nil {
		return err
	}

	return nil
}

func (r *AcrPullBindingReconciler) setErrStatus(ctx context.Context, err error, acrBinding *msiacrpullv1beta2.AcrPullBinding) error {
	acrBinding.Status.Error = err.Error()
	if err := r.Status().Update(ctx, acrBinding); err != nil {
		return err
	}

	return nil
}

func updatePullSecret(pullSecret *v1.Secret, dockerConfig string) *v1.Secret {
	pullSecret.Data[dockerConfigKey] = []byte(dockerConfig)
	return pullSecret
}

func appendImagePullSecretRef(serviceAccount *v1.ServiceAccount, secretName string) {
	secretReference := &v1.LocalObjectReference{
		Name: secretName,
	}
	serviceAccount.ImagePullSecrets = append(serviceAccount.ImagePullSecrets, *secretReference)
}

func imagePullSecretRefExist(imagePullSecretRefs []v1.LocalObjectReference, secretName string) bool {
	if imagePullSecretRefs == nil {
		return false
	}
	for _, secretRef := range imagePullSecretRefs {
		if secretRef.Name == secretName {
			return true
		}
	}
	return false
}

func removeImagePullSecretRef(imagePullSecretRefs []v1.LocalObjectReference, secretName string) []v1.LocalObjectReference {
	var result []v1.LocalObjectReference
	for _, secretRef := range imagePullSecretRefs {
		if secretRef.Name == secretName {
			continue
		}
		result = append(result, secretRef)
	}
	return result
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) []string {
	var result []string
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return result
}

func getServiceAccountName(userSpecifiedName string) string {
	if userSpecifiedName != "" {
		return userSpecifiedName
	}
	return defaultServiceAccountName
}

func getPullSecretName(acrBindingName string) string {
	return fmt.Sprintf("%s-msi-acrpull-secret", acrBindingName)
}

func getPullSecret(acrBinding *msiacrpullv1beta2.AcrPullBinding, pullSecrets []v1.Secret) *v1.Secret {
	if pullSecrets == nil {
		return nil
	}

	pullSecretName := getPullSecretName(acrBinding.Name)

	for idx, secret := range pullSecrets {
		if secret.Name == pullSecretName {
			return &pullSecrets[idx]
		}
	}

	return nil
}

func newBasePullSecret(acrBinding *msiacrpullv1beta2.AcrPullBinding,
	dockerConfig string, scheme *runtime.Scheme) (*v1.Secret, error) {

	pullSecret := &v1.Secret{
		Type: v1.SecretTypeDockerConfigJson,
		ObjectMeta: metav1.ObjectMeta{
			Labels:      map[string]string{},
			Annotations: map[string]string{},
			Name:        getPullSecretName(acrBinding.Name),
			Namespace:   acrBinding.Namespace,
		},
		Data: map[string][]byte{
			dockerConfigKey: []byte(dockerConfig),
		},
	}

	if err := ctrl.SetControllerReference(acrBinding, pullSecret, scheme); err != nil {
		return nil, errors.Wrap(err, "failed to create Acr ImagePullSecret")
	}

	return pullSecret, nil
}

func getTokenRefreshDuration(accessToken types.AccessToken) time.Duration {
	exp, err := accessToken.GetTokenExp()
	if err != nil {
		return 0
	}

	refreshDuration := exp.Sub(time.Now().Add(tokenRefreshBuffer))
	if refreshDuration < 0 {
		return 0
	}

	return refreshDuration
}
