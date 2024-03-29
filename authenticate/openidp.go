package authenticate

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/alwitt/goutils"
	"github.com/alwitt/padlock/common"
	"github.com/apex/log"
	"github.com/golang-jwt/jwt/v4"
)

// OpenIDIssuerClient a client to interact with an OpenID issuer
type OpenIDIssuerClient interface {
	/*
		AssociatedPublicKey fetches the associated public based on "kid" value of a JWT token

		 @param token *jwt.Token - the JWT token to find the public key for
		 @return public key material
	*/
	AssociatedPublicKey(token *jwt.Token) (interface{}, error)

	/*
		ParseJWT parses a string into a JWT token object.

		 @param raw string - the original JWT string
		 @param claimStore jwt.Claims - the object to store the claims in
		 @return the parsed JWT token object
	*/
	ParseJWT(raw string, claimStore jwt.Claims) (*jwt.Token, error)

	/*
		CanIntrospect whether the client can perform introspection

		 @return whether the client can perform introspection
	*/
	CanIntrospect() bool

	/*
		IntrospectToken perform introspection for a token

		 @param ctxt context.Context - the operating context
		 @param token string - the token to introspect
		 @return whether token is still valid
	*/
	IntrospectToken(ctxt context.Context, token string) (bool, error)
}

// OpenIDIssuerConfig holds the OpenID issuer's API info.
//
// This is typically read from http://{{ OpenID issuer }}/.well-known/openid-configuration.
//
// The current structure is mainly based around the response from KeyCloak
type OpenIDIssuerConfig struct {
	Issuer               string   `json:"issuer"`
	AuthorizationEP      string   `json:"authorization_endpoint"`
	TokenEP              string   `json:"token_endpoint"`
	IntrospectionEP      string   `json:"introspection_endpoint"`
	TokenIntrospectionEP string   `json:"token_introspection_endpoint"`
	UserinfoEP           string   `json:"userinfo_endpoint"`
	EndSessionEP         string   `json:"end_session_endpoint"`
	JwksURI              string   `json:"jwks_uri"`
	ClientRegistrationEP string   `json:"registration_endpoint"`
	RevocationEP         string   `json:"revocation_endpoint"`
	TokenEPAuthMethods   []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported      []string `json:"claims_supported"`
}

// OIDSigningJWK the public key used by the OpenID issuer to sign tokens
type OIDSigningJWK struct {
	Algorithm string `json:"alg"`
	Exponent  string `json:"e"`
	Modulus   string `json:"n"`
	ID        string `json:"kid"`
	Type      string `json:"kty"`
	Use       string `json:"use"`
}

// openIDIssuerClientImpl implements OpenIDIssuerClient
type openIDIssuerClientImpl struct {
	goutils.Component
	cfg          OpenIDIssuerConfig
	hostOverride *string
	httpClient   *http.Client
	publicKey    map[string]interface{}
	clientID     *string
	clientSecret *string
}

/*
DefineOpenIDClient defines a new OpenID issuer client

	@param idpConfig common.OpenIDIssuerConfig - OpenID issuer parameters
	@param httpClient *http.Client - the HTTP client to use to communicate with the OpenID issuer
	@return new client instance
*/
func DefineOpenIDClient(
	idpConfig common.OpenIDIssuerConfig, httpClient *http.Client,
) (OpenIDIssuerClient, error) {
	logTags := log.Fields{
		"module": "authenticate", "component": "openid-client", "issuer": idpConfig.Issuer,
	}

	// Read the OpenID config first
	var cfg OpenIDIssuerConfig
	cfgEP := fmt.Sprintf("%s/.well-known/openid-configuration", idpConfig.Issuer)
	log.WithFields(logTags).Debugf("OpenID issuer config at %s", cfgEP)
	resp, err := httpClient.Get(cfgEP)
	if err != nil {
		log.WithError(err).WithFields(logTags).Errorf("GET %s call failure", cfgEP)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("reading OpenID configuration from %s returned %d", cfgEP, resp.StatusCode)
		log.WithError(err).WithFields(logTags).Errorf("GET %s unsuccessful", cfgEP)
		return nil, err
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		log.WithError(err).WithFields(logTags).Errorf("Failed to parse %s response", cfgEP)
		return nil, err
	}

	// Read the issuer's signing public key
	resp, err = httpClient.Get(cfg.JwksURI)
	if err != nil {
		log.WithError(err).WithFields(logTags).Errorf("GET %s unsuccessful", cfg.JwksURI)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("reading JWKS from %s returned %d", cfg.JwksURI, resp.StatusCode)
		log.WithError(err).WithFields(logTags).Errorf("GET %s unsuccessful", cfg.JwksURI)
		return nil, err
	}
	type jwksResp struct {
		Keys []OIDSigningJWK `json:"keys"`
	}
	var signingKeys jwksResp
	if err := json.NewDecoder(resp.Body).Decode(&signingKeys); err != nil {
		log.WithError(err).WithFields(logTags).Errorf("Failed to parse %s response", cfg.JwksURI)
		return nil, err
	}

	// Perform post processing on the keys
	keyMaterial := make(map[string]interface{})
	for _, key := range signingKeys.Keys {
		n := new(big.Int)
		var pubKey interface{}

		nBytes, _ := base64.RawURLEncoding.DecodeString(key.Modulus)
		n.SetBytes(nBytes)

		eBytes, _ := base64.RawURLEncoding.DecodeString(key.Exponent)
		e := int(new(big.Int).SetBytes(eBytes).Int64())

		switch key.Type {
		case "RSA":
			pubKey = &rsa.PublicKey{N: n, E: e}
		default:
			pubKey = nil
		}

		keyMaterial[key.ID] = pubKey
	}

	{
		t, _ := json.MarshalIndent(&cfg, "", "  ")
		log.WithFields(logTags).Debugf("OpenID issuer parameters\n%s", t)
	}

	if idpConfig.RequestHostOverride != nil {
		log.WithFields(logTags).Warnf(
			"Using host override '%s' when communicating with IDP", *idpConfig.RequestHostOverride,
		)
	}

	return &openIDIssuerClientImpl{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
				common.ModifyLogMetadataByAccessAuthorizeParam,
			},
		},
		cfg:          cfg,
		hostOverride: idpConfig.RequestHostOverride,
		httpClient:   httpClient,
		publicKey:    keyMaterial,
		clientID:     idpConfig.ClientID,
		clientSecret: idpConfig.ClientCred,
	}, nil
}

/*
AssociatedPublicKey fetches the associated public based on "kid" value of a JWT token

	@param token *jwt.Token - the JWT token to find the public key for
	@return public key material
*/
func (c *openIDIssuerClientImpl) AssociatedPublicKey(token *jwt.Token) (interface{}, error) {
	kidRaw, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("jwt missing 'kid' field")
	}
	kid, ok := kidRaw.(string)
	if !ok {
		return nil, fmt.Errorf("jwt 'kid' field does not contain a string")
	}
	if pubKey, ok := c.publicKey[kid]; ok {
		return pubKey, nil
	}
	msg := fmt.Sprintf("Encountered JWT referring public key %s which is unknown", kid)
	log.WithFields(c.LogTags).Errorf(msg)
	return nil, fmt.Errorf(msg)
}

/*
ParseJWT parses a string into a JWT token object.

	@param raw string - the original JWT string
	@param claimStore jwt.Claims - the object to store the claims in
	@return the parsed JWT token object
*/
func (c *openIDIssuerClientImpl) ParseJWT(raw string, claimStore jwt.Claims) (*jwt.Token, error) {
	return jwt.ParseWithClaims(raw, claimStore, c.AssociatedPublicKey)
}

// Potential response from introspection
type introspectResponse struct {
	ID                string           `json:"jti"`
	Expire            int64            `json:"exp"`
	NotValidBefore    int64            `json:"nbf"`
	IssuedAt          int64            `json:"iat"`
	Issuer            string           `json:"iss"`
	Audience          jwt.ClaimStrings `json:"aud"`
	TokenType         string           `json:"typ"`
	AuthorizedParty   string           `json:"azp"`
	AuthenticateTime  int64            `json:"auth_time"`
	SessionState      string           `json:"session_state"`
	PerferredUsername string           `json:"preferred_username"`
	Email             string           `json:"email"`
	VerifiedEmail     bool             `json:"email_verified"`
	AuthnContextClass string           `json:"acr"`
	AllowedOrigins    []string         `json:"allowed-origins"`
	Scope             string           `json:"scope"`
	ClientID          string           `json:"client_id"`
	Username          string           `json:"username"`
	Active            bool             `json:"active"`
}

/*
CanIntrospect whether the client can perform introspection

	@return whether the client can perform introspection
*/
func (c *openIDIssuerClientImpl) CanIntrospect() bool {
	if c.clientID == nil || c.clientSecret == nil || c.cfg.IntrospectionEP == "" {
		// Introspection require
		// * Introspection endpoint
		// * Client ID
		// * Client secret
		return false
	}
	return true
}

/*
IntrospectToken perform introspection for a token

	@param ctxt context.Context - the operating context
	@param token string - the token to introspect
	@return whether token is still valid
*/
func (c *openIDIssuerClientImpl) IntrospectToken(ctxt context.Context, token string) (bool, error) {
	logtags := c.GetLogTagsForContext(ctxt)
	if c.clientID == nil || c.clientSecret == nil || c.cfg.IntrospectionEP == "" {
		// Introspection require
		// * Introspection endpoint
		// * Client ID
		// * Client secret
		log.WithFields(logtags).Error("Missing required settings to perform introspection")
		return false, fmt.Errorf("missing required settings to perform introspection")
	}

	var response introspectResponse
	introspectURL := c.cfg.IntrospectionEP

	// Prepare the request
	requestBody := []byte(fmt.Sprintf("token=%s", token))
	req, err := http.NewRequest("POST", introspectURL, bytes.NewBuffer(requestBody))
	if err != nil {
		log.WithError(err).WithFields(logtags).Error("Failed to define introspect POST request")
		return false, err
	}
	req.SetBasicAuth(*c.clientID, *c.clientSecret)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.hostOverride != nil {
		req.Host = *c.hostOverride
	}

	// Perform the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.WithError(err).WithFields(logtags).Errorf("Introspect against %s failed", introspectURL)
		return false, err
	}
	defer resp.Body.Close()

	// Parse the response
	body, _ := io.ReadAll(resp.Body)
	{
		log.WithFields(logtags).Debugf("Raw introspect response %s", body)
	}
	if err := json.Unmarshal(body, &response); err != nil {
		log.WithError(err).WithFields(logtags).Error("Failed to process introspect response")
		return false, err
	}

	return response.Active, nil
}
