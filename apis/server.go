package apis

import (
	"fmt"
	"net/http"
	"time"

	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/users"
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
*/
func BuildUserManagementServer(
	httpCfg common.HTTPConfig,
	manager users.Management,
	validateSupport common.CustomFieldValidator,
) (*http.Server, error) {
	httpHandler, err := defineUserManagementHandler(httpCfg.Logging, manager, validateSupport)
	if err != nil {
		return nil, err
	}

	router := mux.NewRouter()
	mainRouter := registerPathPrefix(router, httpCfg.Endpoints.PathPrefix, nil)
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
		WriteTimeout: time.Second * time.Duration(httpCfg.Server.WriteTimeout),
		ReadTimeout:  time.Second * time.Duration(httpCfg.Server.ReadTimeout),
		IdleTimeout:  time.Second * time.Duration(httpCfg.Server.IdleTimeout),
		Handler:      h2c.NewHandler(router, &http2.Server{}),
	}

	return httpSrv, nil
}
