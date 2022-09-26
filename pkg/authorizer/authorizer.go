package authorizer

import (
	"fmt"

	"github.com/Azure/msi-acrpull/pkg/authorizer/types"
)

// ManagedIdentityAuthorizer is an instance of authorizer
type ManagedIdentityAuthorizer struct {
	managedIdentityTokenRetriever *ManagedIdentityTokenRetriever
	tokenExchanger                ACRTokenExchanger
}

type WorkloadIdentityAuthorizer struct {
	workloadIdentityTokenRetriever *WorkloadIdentityTokenRetriever
	tokenExchanger                 ACRTokenExchanger
}

// NewManagedIdentityAuthorizer returns a managed identity sauthorizer
func NewManagedIdentityAuthorizer() *ManagedIdentityAuthorizer {
	return &ManagedIdentityAuthorizer{
		managedIdentityTokenRetriever: NewManagedIdentityTokenRetriever(),
		tokenExchanger:                NewTokenExchanger(),
	}
}

func NewWorkloadIdentityAuthorizer() *WorkloadIdentityAuthorizer {
	return &WorkloadIdentityAuthorizer{
		workloadIdentityTokenRetriever: NewWorkloadIdentityTokenRetriever(),
		tokenExchanger:                 NewTokenExchanger(),
	}
}

func (az *ManagedIdentityAuthorizer) AcquireACRAccessToken(clientID, identityResourceID, acrFQDN string) (types.AccessToken, error) {
	var err error
	var armToken types.AccessToken

	if clientID != "" {
		armToken, err = az.managedIdentityTokenRetriever.AcquireARMToken(clientID, "")
		if err != nil {
			return "", fmt.Errorf("failed to get ARM access token via client ID: %w", err)
		}
	} else {
		armToken, err = az.managedIdentityTokenRetriever.AcquireARMToken("", identityResourceID)
		if err != nil {
			return "", fmt.Errorf("failed to get ARM access token via identity resource ID: %w", err)
		}
	}

	tenantID, err := getTokenTenantID(armToken)
	if err != nil {
		return "", fmt.Errorf("failed to get token tenant ID: %w", err)
	}

	return az.tokenExchanger.ExchangeACRAccessToken(armToken, tenantID, acrFQDN)
}

func getTokenTenantID(t types.AccessToken) (string, error) {
	claims, err := t.GetTokenClaims()
	if err != nil {
		return "", err
	}
	tenantID, ok := claims["tid"].(string)
	if ok {
		return tenantID, nil
	}

	tenantID, ok = claims["tenant"].(string)
	if ok {
		return tenantID, nil
	}

	return "", fmt.Errorf("token has no tenant ID")
}
