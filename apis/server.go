package apis

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/alwitt/goutils"
	"github.com/alwitt/padlock/authenticate"
	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/match"
	"github.com/alwitt/padlock/users"
	"github.com/apex/log"
	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

/*
BuildMetricsCollectionServer create server to host metrics collection endpoint

	@param httpCfg common.HTTPServerConfig - HTTP server configuration
	@param metricsCollector goutils.MetricsCollector - metrics collector
	@param collectionEndpoint string - endpoint to expose the metrics on
	@param maxRESTRequests int - max number fo parallel requests to support
	@returns HTTP server instance
*/
func BuildMetricsCollectionServer(
	httpCfg common.HTTPServerConfig,
	metricsCollector goutils.MetricsCollector,
	collectionEndpoint string,
	maxRESTRequests int,
) (*http.Server, error) {
	router := mux.NewRouter()
	metricsCollector.ExposeCollectionEndpoint(router, collectionEndpoint, maxRESTRequests)

	serverListen := fmt.Sprintf(
		"%s:%d", httpCfg.ListenOn, httpCfg.Port,
	)
	httpSrv := &http.Server{
		Addr:         serverListen,
		WriteTimeout: time.Second * time.Duration(httpCfg.Timeouts.WriteTimeout),
		ReadTimeout:  time.Second * time.Duration(httpCfg.Timeouts.ReadTimeout),
		IdleTimeout:  time.Second * time.Duration(httpCfg.Timeouts.IdleTimeout),
		Handler:      h2c.NewHandler(router, &http2.Server{}),
	}

	return httpSrv, nil
}

// ====================================================================================
// User Management Server

/*
BuildUserManagementServer creates the user management server

	@param httpCfg common.HTTPConfig - HTTP server config
	@param manager users.Management - core user management logic block
	@param validateSupport common.CustomFieldValidator - customer validator support object
	@param metrics goutils.HTTPRequestMetricHelper - metric collection agent
	@return the http.Server
*/
func BuildUserManagementServer(
	httpCfg common.APIServerConfig,
	manager users.Management,
	validateSupport common.CustomFieldValidator,
	metrics goutils.HTTPRequestMetricHelper,
) (*http.Server, error) {
	coreHandler, err := defineUserManagementHandler(
		httpCfg.APIs.RequestLogging, manager, validateSupport, metrics,
	)
	if err != nil {
		return nil, err
	}
	livenessHandler := defineUserManagementLivenessHandler(httpCfg.APIs.RequestLogging, manager)

	router := mux.NewRouter()
	mainRouter := registerPathPrefix(router, httpCfg.APIs.Endpoint.PathPrefix, nil)
	livenessRouter := registerPathPrefix(mainRouter, "/liveness", nil)
	v1Router := registerPathPrefix(mainRouter, "/v1", nil)

	// Role management
	roleRouter := registerPathPrefix(v1Router, "/role", map[string]http.HandlerFunc{
		"get": coreHandler.ListAllRolesHandler(),
	})
	_ = registerPathPrefix(roleRouter, "/{roleName}", map[string]http.HandlerFunc{
		"get": coreHandler.GetRoleHandler(),
	})

	// User management
	userRouter := registerPathPrefix(v1Router, "/user", map[string]http.HandlerFunc{
		"post": coreHandler.DefineUserHandler(),
		"get":  coreHandler.ListAllUsersHandler(),
	})
	perUserRouter := registerPathPrefix(userRouter, "/{userID}", map[string]http.HandlerFunc{
		"get":    coreHandler.GetUserHandler(),
		"delete": coreHandler.DeleteUserHandler(),
		"put":    coreHandler.UpdateUserHandler(),
	})
	_ = registerPathPrefix(perUserRouter, "/roles", map[string]http.HandlerFunc{
		"put": coreHandler.UpdateUserRolesHandler(),
	})

	// Health check
	_ = registerPathPrefix(livenessRouter, "/alive", map[string]http.HandlerFunc{
		"get": livenessHandler.AliveHandler(),
	})
	_ = registerPathPrefix(livenessRouter, "/ready", map[string]http.HandlerFunc{
		"get": livenessHandler.ReadyHandler(),
	})

	// Add logging middleware
	v1Router.Use(func(next http.Handler) http.Handler {
		return coreHandler.LoggingMiddleware(next.ServeHTTP)
	})
	livenessRouter.Use(func(next http.Handler) http.Handler {
		return livenessHandler.LoggingMiddleware(next.ServeHTTP)
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
	@param metrics goutils.HTTPRequestMetricHelper - metric collection agent
	@return the http.Server
*/
func BuildAuthorizationServer(
	httpCfg common.APIServerConfig,
	manager users.Management,
	requestMatcher match.RequestMatch,
	validateSupport common.CustomFieldValidator,
	checkHeaders common.AuthorizeRequestParamLocConfig,
	forUnknownUser common.UnknownUserActionConfig,
	metrics goutils.HTTPRequestMetricHelper,
) (*http.Server, error) {
	coreHandler, err := defineAuthorizationHandler(
		httpCfg.APIs.RequestLogging,
		manager,
		requestMatcher,
		validateSupport,
		checkHeaders,
		forUnknownUser,
		metrics,
	)
	if err != nil {
		return nil, err
	}
	livenessHandler := defineAuthorizationLivenessHandler(httpCfg.APIs.RequestLogging, manager)

	router := mux.NewRouter()
	mainRouter := registerPathPrefix(router, httpCfg.APIs.Endpoint.PathPrefix, nil)
	livenessRouter := registerPathPrefix(mainRouter, "/liveness", nil)
	v1Router := registerPathPrefix(mainRouter, "/v1", nil)

	// Authorize
	_ = registerPathPrefix(v1Router, "/allow", map[string]http.HandlerFunc{
		"get": coreHandler.AllowHandler(),
	})

	// Health check
	_ = registerPathPrefix(livenessRouter, "/alive", map[string]http.HandlerFunc{
		"get": livenessHandler.AliveHandler(),
	})
	_ = registerPathPrefix(livenessRouter, "/ready", map[string]http.HandlerFunc{
		"get": livenessHandler.ReadyHandler(),
	})

	// Add logging middleware
	v1Router.Use(func(next http.Handler) http.Handler {
		return coreHandler.LoggingMiddleware(next.ServeHTTP)
	})
	livenessRouter.Use(func(next http.Handler) http.Handler {
		return livenessHandler.LoggingMiddleware(next.ServeHTTP)
	})

	// Add request parameter extract middleware
	v1Router.Use(func(next http.Handler) http.Handler {
		return coreHandler.ParamReadMiddleware(next.ServeHTTP)
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

	@param parentCtx context.Context
	@param httpCfg common.HTTPConfig - HTTP server config
	@param openIDCfg common.OpenIDIssuerConfig - OpenID issuer configuration
	@parem performIntrospection bool - whether to perform introspection
	@param tokenCache authenticate.TokenCache - cache to reduce number of introspections
	@param authnConfig common.AuthenticationConfig - authentication submodule configuration
	@param respHeaderParam common.AuthorizeRequestParamLocConfig - config which indicates what
	response headers to output the user parameters on.
	@param metrics goutils.HTTPRequestMetricHelper - metric collection agent
	@return the http.Server
*/
func BuildAuthenticationServer(
	parentCtx context.Context,
	httpCfg common.APIServerConfig,
	openIDCfg common.OpenIDIssuerConfig,
	performIntrospection bool,
	tokenCache authenticate.TokenCache,
	authnConfig common.AuthenticationConfig,
	respHeaderParam common.AuthorizeRequestParamLocConfig,
	metrics goutils.HTTPRequestMetricHelper,
) (*http.Server, error) {
	oidpHTTPClient, err := goutils.DefineHTTPClient(
		parentCtx,
		goutils.HTTPClientRetryConfig{
			MaxAttempts:  6,
			InitWaitTime: 5,
			MaxWaitTime:  30,
		},
		nil,
		&goutils.HTTPClientTransportConfig{CustomCA: openIDCfg.CustomCA},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to define HTTP client for OIDP client [%w]", err)
	}

	oidpTargetAudience := []string{}
	if authnConfig.TargetAudience != nil {
		oidpTargetAudience = append(oidpTargetAudience, *authnConfig.TargetAudience)
	}

	oidpClient, err := goutils.DefineOpenIDProviderClient(
		goutils.OIDPClientParam{
			Issuer:              openIDCfg.Issuer,
			ClientID:            openIDCfg.ClientID,
			ClientCred:          openIDCfg.ClientCred,
			RequestHostOverride: openIDCfg.RequestHostOverride,
			TargetAudiences:     oidpTargetAudience,
			LogTags:             log.Fields{"module": "apis", "component": "oidp-client"},
		}, oidpHTTPClient,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to define OIDP client [%w]", err)
	}

	jwtCheckMiddleware := goutils.DefineJWTCheckMiddleware(
		oidpClient, log.Fields{"module": "apis", "component": "jwt-check-middleware"},
	)

	introspector := authenticate.DefineIntrospector(tokenCache, oidpClient.IntrospectToken)
	coreHandler, err := defineAuthenticationHandler(
		httpCfg.APIs.RequestLogging,
		oidpClient,
		performIntrospection,
		introspector,
		authnConfig,
		respHeaderParam,
		metrics,
	)
	if err != nil {
		return nil, err
	}
	livenessHandler := defineAuthenticationLivenessHandler(httpCfg.APIs.RequestLogging)

	router := mux.NewRouter()
	mainRouter := registerPathPrefix(router, httpCfg.APIs.Endpoint.PathPrefix, nil)
	livenessRouter := registerPathPrefix(mainRouter, "/liveness", nil)
	v1Router := registerPathPrefix(mainRouter, "/v1", nil)

	// Authentication
	_ = registerPathPrefix(v1Router, "/authenticate", map[string]http.HandlerFunc{
		"get": coreHandler.AuthenticateHandler(),
	})

	// Health check
	_ = registerPathPrefix(livenessRouter, "/alive", map[string]http.HandlerFunc{
		"get": livenessHandler.AliveHandler(),
	})
	_ = registerPathPrefix(livenessRouter, "/ready", map[string]http.HandlerFunc{
		"get": livenessHandler.ReadyHandler(),
	})

	// Add logging middleware
	v1Router.Use(func(next http.Handler) http.Handler {
		return coreHandler.LoggingMiddleware(next.ServeHTTP)
	})
	// Add JWT parsing middleware
	v1Router.Use(func(next http.Handler) http.Handler {
		return jwtCheckMiddleware.ParseAndValidateJWT(next.ServeHTTP)
	})
	livenessRouter.Use(func(next http.Handler) http.Handler {
		return livenessHandler.LoggingMiddleware(next.ServeHTTP)
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
