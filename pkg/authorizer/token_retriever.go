package authorizer

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/msi-acrpull/pkg/authorizer/types"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

const (
	defaultARMResource              = "https://management.azure.com/"
	customARMResourceEnvVar         = "ARM_RESOURCE"
	defaultCacheExpirationInSeconds = 600
)

type baseTokenRetriever struct {
	cache           sync.Map
	cacheExpiration time.Duration
}

type ManagedIdentityTokenRetriever struct {
	baseTokenRetriever
	metadataEndpoint string
}

type WorkloadIdentityTokenRetriever struct {
	baseTokenRetriever
}

type cachedToken struct {
	token    types.AccessToken
	notAfter time.Time
}

// NewManagedIdentityTokenRetriever returns a new managed identity token retriever
func NewManagedIdentityTokenRetriever() *ManagedIdentityTokenRetriever {
	const msiMetadataEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"
	return &ManagedIdentityTokenRetriever{
		baseTokenRetriever: baseTokenRetriever{
			cache:           sync.Map{},
			cacheExpiration: time.Duration(defaultCacheExpirationInSeconds) * time.Second,
		},
		metadataEndpoint: msiMetadataEndpoint,
	}
}

// AcquireARMToken acquires the managed identity ARM access token
func (tr *ManagedIdentityTokenRetriever) AcquireARMToken(clientID string, resourceID string) (types.AccessToken, error) {
	cacheKey := strings.ToLower(clientID)
	if cacheKey == "" {
		cacheKey = strings.ToLower(resourceID)
	}

	cached, ok := tr.cache.Load(cacheKey)
	if ok {
		token := cached.(cachedToken)
		if time.Now().UTC().Sub(token.notAfter) < 0 {
			return token.token, nil
		}

		tr.cache.Delete(cacheKey)
	}

	token, err := tr.refreshToken(clientID, resourceID)
	if err != nil {
		return "", fmt.Errorf("failed to refresh ARM access token: %w", err)
	}

	tr.cache.Store(cacheKey, cachedToken{token: token, notAfter: time.Now().UTC().Add(tr.cacheExpiration)})
	return token, nil
}

func (tr *ManagedIdentityTokenRetriever) refreshToken(clientID, resourceID string) (types.AccessToken, error) {
	msiEndpoint, err := url.Parse(tr.metadataEndpoint)
	if err != nil {
		return "", err
	}

	parameters := url.Values{}
	if clientID != "" {
		parameters.Add("client_id", clientID)
	} else {
		parameters.Add("mi_res_id", resourceID)
	}

	customARMResource := os.Getenv(customARMResourceEnvVar)
	if customARMResource == "" {
		parameters.Add("resource", defaultARMResource)
	} else {
		parameters.Add("resource", customARMResource)
	}

	parameters.Add("api-version", "2018-02-01")

	msiEndpoint.RawQuery = parameters.Encode()

	req, err := http.NewRequest("GET", msiEndpoint.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Metadata", "true")

	client := &http.Client{}
	var resp *http.Response
	defer closeResponse(resp)

	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send metadata endpoint request: %w", err)
	}

	if resp.StatusCode != 200 {
		responseBytes, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("Metadata endpoint returned error status: %d. body: %s", resp.StatusCode, string(responseBytes))
	}

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read metadata endpoint response: %w", err)
	}

	var tokenResp tokenResponse
	err = json.Unmarshal(responseBytes, &tokenResp)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal metadata endpoint response: %w", err)
	}

	return types.AccessToken(tokenResp.AccessToken), nil
}

// NewWorkloadIdentityTokenRetriever returns a new workload identity token retriever
func NewWorkloadIdentityTokenRetriever() *WorkloadIdentityTokenRetriever {
	return &WorkloadIdentityTokenRetriever{
		baseTokenRetriever: baseTokenRetriever{
			cache:           sync.Map{},
			cacheExpiration: time.Duration(defaultCacheExpirationInSeconds) * time.Second,
		},
	}
}

func (tr *WorkloadIdentityTokenRetriever) AcquireARMToken(ctx context.Context, clientID, tenantID, acrFQDN string) (types.AccessToken, error) {
	const authorityHost = "https://login.microsoftonline.com/"

	// Check if token is in the cache
	cacheKey := strings.ToLower(clientID)
	cached, ok := tr.cache.Load(cacheKey)
	if ok {
		token := cached.(cachedToken)
		if time.Now().UTC().Sub(token.notAfter) < 0 {
			return token.token, nil
		}

		tr.cache.Delete(cacheKey)
	}

	// Get auth token from service account token
	cred := confidential.NewCredFromAssertionCallback(func(context.Context, confidential.AssertionRequestOptions) (string, error) {
		return readJWTFromFS()
	})

	confidentialClientApp, err := confidential.New(
		clientID,
		cred,
		confidential.WithAuthority(fmt.Sprintf("%s%s/oauth2/token", authorityHost, tenantID)))
	if err != nil {
		return "", fmt.Errorf("Unable to get new confidential client app: %w", err)
	}

	resource := os.Getenv(customARMResourceEnvVar)
	if resource == "" {
		resource = defaultARMResource
	}

	resource = strings.TrimSuffix(resource, "/")
	if !strings.HasSuffix(resource, ".default") {
		// .default needs to be added to the scope
		resource += "/.default"
	}

	authResult, err := confidentialClientApp.AcquireTokenByCredential(ctx, []string{resource})
	if err != nil {
		return "", fmt.Errorf("Unable to acquire bearer token for clientID %s: %w.", clientID, err)
	}

	return types.AccessToken(authResult.AccessToken), nil
}

func closeResponse(resp *http.Response) {
	if resp == nil {
		return
	}
	resp.Body.Close()
}

func readJWTFromFS() (string, error) {
	const SATokenPath = "/var/run/secrets/token/saToken"

	f, err := os.ReadFile(SATokenPath)
	if err != nil {
		return "", err
	}

	return string(f), nil
}
