package apis

import (
	"net/http"

	"github.com/alwitt/padlock/common"
	"github.com/apex/log"
)

// AuthenticationHandler the request authentication REST API handler
type AuthenticationHandler struct {
	APIRestHandler
}

// DefineAuthenticationHandler define a new AuthenticationHandler instance
func DefineAuthenticationHandler(
	logConfig common.HTTPRequestLogging,
) (AuthenticationHandler, error) {
	logTags := log.Fields{
		"module": "apis", "component": "api-handler", "instance": "authentication",
	}

	return AuthenticationHandler{
		APIRestHandler: APIRestHandler{
			Component: common.Component{LogTags: logTags},
			offLimitHeadersForLog: func() map[string]bool {
				result := map[string]bool{}
				for _, v := range logConfig.DoNotLogHeaders {
					result[v] = true
				}
				return result
			}(),
		},
	}, nil
}

// ====================================================================================
// Authenticate

// Authenticate godoc
// @Summary Authenticate a user
// @Description Authticate a user by verifiying the bearer token provided
// @tags Management
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Param Authorization header string true "User must provide a bearer token"
// @Success 200 {object} BaseResponse "success"
// @Failure 400 {string} BaseResponse "error"
// @Failure 401 {string} string "error"
// @Failure 403 {string} string "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} BaseResponse "error"
// @Router /v1/authenticate [get]
func (h AuthenticationHandler) Authenticate(w http.ResponseWriter, r *http.Request) {
	logTags := h.GetLogTagsForContext(r.Context())
	if err := writeRESTResponse(
		w, r, http.StatusOK, getStdRESTSuccessMsg(r.Context()), nil,
	); err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to form response")
	}
}

// AuthenticateHandler Wrapper around Authenticate
func (h AuthenticationHandler) AuthenticateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Authenticate(w, r)
	}
}

// ====================================================================================
// Utilities

// Alive godoc
// @Summary Authentication API liveness check
// @Description Will return success to indicate Authentication REST API module is live
// @tags Management
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Success 200 {object} BaseResponse "success"
// @Failure 400 {string} BaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} BaseResponse "error"
// @Router /v1/alive [get]
func (h AuthenticationHandler) Alive(w http.ResponseWriter, r *http.Request) {
	logTags := h.GetLogTagsForContext(r.Context())
	if err := writeRESTResponse(
		w, r, http.StatusOK, getStdRESTSuccessMsg(r.Context()), nil,
	); err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to form response")
	}
}

// AliveHandler Wrapper around Alive
func (h AuthenticationHandler) AliveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Alive(w, r)
	}
}

// -----------------------------------------------------------------------

// Ready godoc
// @Summary Authentication API readiness check
// @Description Will return success if Authentication REST API module is ready for use
// @tags Management
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Success 200 {object} BaseResponse "success"
// @Failure 400 {string} BaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} BaseResponse "error"
// @Router /v1/ready [get]
func (h AuthenticationHandler) Ready(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := writeRESTResponse(w, r, respCode, response, nil); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()
	// TODO: once a core logic is in place, refer to that instead for ready.
	respCode = http.StatusOK
	response = getStdRESTSuccessMsg(r.Context())
}

// ReadyHandler Wrapper around Alive
func (h AuthenticationHandler) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Ready(w, r)
	}
}
