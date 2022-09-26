package authorizer

import "github.com/Azure/msi-acrpull/pkg/authorizer/types"

//go:generate sh -c "mockgen github.com/Azure/msi-acrpull/pkg/authorizer Interface,ManagedIdentityTokenRetriever,ACRTokenExchanger > ./mock_$GOPACKAGE/interfaces.go"

// Interface is the authorizer interface to acquire ACR access tokens.
type Interface interface {
	AcquireACRAccessTokenWithResourceID(identityResourceID string, acrFQDN string) (types.AccessToken, error)
	AcquireACRAccessTokenWithClientID(clientID string, acrFQDN string) (types.AccessToken, error)
}

// ACRTokenExchanger is the interface to exchange an ACR access token.
type ACRTokenExchanger interface {
	ExchangeACRAccessToken(armToken types.AccessToken, tenantID, acrFQDN string) (types.AccessToken, error)
}
