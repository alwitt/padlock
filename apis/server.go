package apis

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/alwitt/padlock/authenticate"
	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/match"
	"github.com/alwitt/padlock/users"
	"github.com/apex/log"
	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// ====================================================================================
// User Management Server

/*
BuildUserManagementServer creates the user management server

	@param httpCfg common.HTTPConfig - HTTP server config
	@param manager users.Management - core user management logic block
	@param validateSupport common.CustomFieldValidator - customer validator support object
	@return the http.Server
*/
func BuildUserManagementServer(
	httpCfg common.APIServerConfig,
	manager users.Management,
	validateSupport common.CustomFieldValidator,
) (*http.Server, error) {
	httpHandler, err := defineUserManagementHandler(
		httpCfg.APIs.RequestLogging, manager, validateSupport,
	)
	if err != nil {
		return nil, err
	}

	router := mux.NewRouter()
	mainRouter := registerPathPrefix(router, httpCfg.APIs.Endpoint.PathPrefix, nil)
	v1Router := registerPathPrefix(mainRouter, "/v1", nil)

	// Role management
	roleRouter := registerPathPrefix(v1Router, "/role", map[string]http.HandlerFunc{
		"get": httpHandler.ListAllRolesHandler(),
	})
	_ = registerPathPrefix(roleRouter, "/{roleName}", map[string]http.HandlerFunc{
		"get": httpHandler.GetRoleHandler(),
	})

	// User management
	userRouter := registerPathPrefix(v1Router, "/user", map[string]http.HandlerFunc{
		"post": httpHandler.DefineUserHandler(),
		"get":  httpHandler.ListAllUsersHandler(),
	})
	perUserRouter := registerPathPrefix(userRouter, "/{userID}", map[string]http.HandlerFunc{
		"get":    httpHandler.GetUserHandler(),
		"delete": httpHandler.DeleteUserHandler(),
		"put":    httpHandler.UpdateUserHandler(),
	})
	_ = registerPathPrefix(perUserRouter, "/roles", map[string]http.HandlerFunc{
		"put": httpHandler.UpdateUserRolesHandler(),
	})

	// Health check
	_ = registerPathPrefix(v1Router, "/alive", map[string]http.HandlerFunc{
		"get": httpHandler.AliveHandler(),
	})
	_ = registerPathPrefix(v1Router, "/ready", map[string]http.HandlerFunc{
		"get": httpHandler.ReadyHandler(),
	})

	// Add logging middleware
	router.Use(func(next http.Handler) http.Handler {
		return httpHandler.LoggingMiddleware(next.ServeHTTP)
	})

	serverListen := fmt.Sprintf(
		"%s:%d", httpCfg.Server.ListenOn, httpCfg.Server.Port,
	)
	httpSrv := &http.Server{
		Addr:         serverListen,
		WriteTimeout: time.Second * time.Duration(httpCfg.Server.Timeouts.WriteTimeout),
		ReadTimeout:  time.Second * time.Duration(httpCfg.Server.Timeouts.ReadTimeout),
		IdleTimeout:  time.Second * time.Duration(httpCfg.Server.Timeouts.IdleTimeout),
		Handler:      h2c.NewHandler(router, &http2.Server{}),
	}

	return httpSrv, nil
}

// ====================================================================================
// Authorization Server

/*
BuildAuthorizationServer creates the authorization server

	@param httpCfg common.HTTPConfig - HTTP server config
	@param manager users.Management - core user management logic block
	@param requestMatcher match.RequestMatch - the request matcher
	@param validateSupport common.CustomFieldValidator - customer validator support object
	@param checkHeaders common.AuthorizeRequestParamLocConfig - param on which headers to search for
	parameters regarding a REST API to authorize.
	@param forUnknownUser common.UnknownUserActionConfig - param on how to handle new unknown user
	@return the http.Server
*/
func BuildAuthorizationServer(
	httpCfg common.APIServerConfig,
	manager users.Management,
	requestMatcher match.RequestMatch,
	validateSupport common.CustomFieldValidator,
	checkHeaders common.AuthorizeRequestParamLocConfig,
	forUnknownUser common.UnknownUserActionConfig,
) (*http.Server, error) {
	httpHandler, err := defineAuthorizationHandler(
		httpCfg.APIs.RequestLogging,
		manager,
		requestMatcher,
		validateSupport,
		checkHeaders,
		forUnknownUser,
	)
	if err != nil {
		return nil, err
	}

	router := mux.NewRouter()
	mainRouter := registerPathPrefix(router, httpCfg.APIs.Endpoint.PathPrefix, nil)
	v1Router := registerPathPrefix(mainRouter, "/v1", nil)

	// Authorize
	_ = registerPathPrefix(v1Router, "/allow", map[string]http.HandlerFunc{
		"get": httpHandler.AllowHandler(),
	})

	// Health check
	_ = registerPathPrefix(v1Router, "/alive", map[string]http.HandlerFunc{
		"get": httpHandler.AliveHandler(),
	})
	_ = registerPathPrefix(v1Router, "/ready", map[string]http.HandlerFunc{
		"get": httpHandler.ReadyHandler(),
	})

	// Add logging middleware
	router.Use(func(next http.Handler) http.Handler {
		return httpHandler.LoggingMiddleware(next.ServeHTTP)
	})

	// Add request parameter extract middleware
	router.Use(func(next http.Handler) http.Handler {
		return httpHandler.ParamReadMiddleware(next.ServeHTTP)
	})

	serverListen := fmt.Sprintf(
		"%s:%d", httpCfg.Server.ListenOn, httpCfg.Server.Port,
	)
	httpSrv := &http.Server{
		Addr:         serverListen,
		WriteTimeout: time.Second * time.Duration(httpCfg.Server.Timeouts.WriteTimeout),
		ReadTimeout:  time.Second * time.Duration(httpCfg.Server.Timeouts.ReadTimeout),
		IdleTimeout:  time.Second * time.Duration(httpCfg.Server.Timeouts.IdleTimeout),
		Handler:      h2c.NewHandler(router, &http2.Server{}),
	}

	return httpSrv, nil
}

// ====================================================================================
// Authentication Server

/*
BuildAuthenticationServer creates the authentication server

	@param httpCfg common.HTTPConfig - HTTP server config
	@param openIDCfg common.OpenIDIssuerConfig - OpenID issuer configuration
	@param targetClaims common.OpenIDClaimsOfInterestConfig - config which JWT token claims to parse
	to fetch a user's parameters.
	@param respHeaderParam common.AuthorizeRequestParamLocConfig - config which indicates what
	response headers to output the user parameters on.
	@return the http.Server
*/
func BuildAuthenticationServer(
	httpCfg common.APIServerConfig,
	openIDCfg common.OpenIDIssuerConfig,
	targetClaims common.OpenIDClaimsOfInterestConfig,
	respHeaderParam common.AuthorizeRequestParamLocConfig,
) (*http.Server, error) {
	// Define custom HTTP client for connecting with OpenID issuer
	oidHTTPClient := http.Client{}
	// Define the TLS settings if custom CA was provided
	if openIDCfg.CustomCA != nil {
		caCert, err := os.ReadFile(*openIDCfg.CustomCA)
		if err != nil {
			log.WithError(err).Errorf("Unable to read %s", *openIDCfg.CustomCA)
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig := &tls.Config{RootCAs: caCertPool}
		oidHTTPClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}

	oidClient, err := authenticate.DefineOpenIDClient(openIDCfg.Issuer, &oidHTTPClient)
	if err != nil {
		return nil, err
	}

	httpHandler, err := defineAuthenticationHandler(
		httpCfg.APIs.RequestLogging, oidClient, targetClaims, respHeaderParam,
	)
	if err != nil {
		return nil, err
	}

	router := mux.NewRouter()
	mainRouter := registerPathPrefix(router, httpCfg.APIs.Endpoint.PathPrefix, nil)
	v1Router := registerPathPrefix(mainRouter, "/v1", nil)

	// Authentication
	_ = registerPathPrefix(v1Router, "/authenticate", map[string]http.HandlerFunc{
		"get": httpHandler.AuthenticateHandler(),
	})

	// Health check
	_ = registerPathPrefix(v1Router, "/alive", map[string]http.HandlerFunc{
		"get": httpHandler.AliveHandler(),
	})
	_ = registerPathPrefix(v1Router, "/ready", map[string]http.HandlerFunc{
		"get": httpHandler.ReadyHandler(),
	})

	// Add logging middleware
	router.Use(func(next http.Handler) http.Handler {
		return httpHandler.LoggingMiddleware(next.ServeHTTP)
	})

	serverListen := fmt.Sprintf(
		"%s:%d", httpCfg.Server.ListenOn, httpCfg.Server.Port,
	)
	httpSrv := &http.Server{
		Addr:         serverListen,
		WriteTimeout: time.Second * time.Duration(httpCfg.Server.Timeouts.WriteTimeout),
		ReadTimeout:  time.Second * time.Duration(httpCfg.Server.Timeouts.ReadTimeout),
		IdleTimeout:  time.Second * time.Duration(httpCfg.Server.Timeouts.IdleTimeout),
		Handler:      h2c.NewHandler(router, &http2.Server{}),
	}

	return httpSrv, nil
}
