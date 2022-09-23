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
	msiMetadataEndpoint             = "http://169.254.169.254/metadata/identity/oauth2/token"
	defaultCacheExpirationInSeconds = 600
	authorityHost                   = "https://login.microsoftonline.com/"
	resource                        = "https://management.azure.com/.default"
)

// TokenRetriever is an instance of ManagedIdentityTokenRetriever
type TokenRetriever struct {
	metadataEndpoint string
	cache            sync.Map
	cacheExpiration  time.Duration
}

type cachedToken struct {
	token    types.AccessToken
	notAfter time.Time
}

// NewTokenRetriever returns a new token retriever
func NewTokenRetriever() *TokenRetriever {
	return &TokenRetriever{
		metadataEndpoint: msiMetadataEndpoint,
		cache:            sync.Map{},
		cacheExpiration:  time.Duration(defaultCacheExpirationInSeconds) * time.Second,
	}
}

// AcquireARMToken acquires the managed identity ARM access token
func (tr *TokenRetriever) AcquireARMToken(clientID string, resourceID string) (types.AccessToken, error) {
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

func (tr *TokenRetriever) refreshToken(clientID, resourceID string) (types.AccessToken, error) {
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

func closeResponse(resp *http.Response) {
	if resp == nil {
		return
	}
	resp.Body.Close()
}

// Get auth token from service account token
func (tr *TokenRetriever) AcquireARMTokenFromServiceAccountToken(ctx context.Context, tenantID, clientID string) (types.AccessToken, error) {
	cacheKey := strings.ToLower(clientID)
	cached, ok := tr.cache.Load(cacheKey)
	if ok {
		token := cached.(cachedToken)
		if time.Now().UTC().Sub(token.notAfter) < 0 {
			return token.token, nil
		}

		tr.cache.Delete(cacheKey)
	}

	// refresh token
	cred := confidential.NewCredFromAssertionCallback(func(context.Context, confidential.AssertionRequestOptions) (string, error) {
		return readJWTFromFS()
	})

	confidentialClientApp, err := confidential.New(
		clientID,
		cred,
		confidential.WithAuthority(fmt.Sprintf("%s%s/oauth2/token", authorityHost, tenantID)))
	if err != nil {
		return "", fmt.Errorf("unable to get new confidential client app: %w", err)
	}

	authResult, err := confidentialClientApp.AcquireTokenByCredential(ctx, []string{resource})
	if err != nil {
		return "", fmt.Errorf("unable to acquire bearer token: %w", err)
	}

	token := types.AccessToken(authResult.AccessToken)
	tr.cache.Store(cacheKey, cachedToken{token: token, notAfter: time.Now().UTC().Add(tr.cacheExpiration)})
	return token, nil
}

func readJWTFromFS() (string, error) {
	const SATokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	f, err := os.ReadFile(SATokenPath)
	if err != nil {
		return "", err
	}

	return string(f), nil
}
