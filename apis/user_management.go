package apis

import (
	"net/http"

	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/users"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
)

// UserManagementHandler the user / role management REST API handler
type UserManagementHandler struct {
	APIRestHandler
	validate *validator.Validate
	core     users.Management
}

// defineUserManagementHandler define a new UserManagementHandler instance
func defineUserManagementHandler(
	logConfig common.HTTPRequestLogging,
	core users.Management,
	validateSupport common.CustomFieldValidator,
) (UserManagementHandler, error) {
	validate := validator.New()
	if err := validateSupport.RegisterWithValidator(validate); err != nil {
		return UserManagementHandler{}, err
	}

	logTags := log.Fields{
		"module": "apis", "component": "api-handler", "instance": "user-management",
	}

	return UserManagementHandler{
		APIRestHandler: APIRestHandler{
			Component:       common.Component{LogTags: logTags},
			endOfRequestLog: logConfig.EndOfRequestMessage,
			offLimitHeadersForLog: func() map[string]bool {
				result := map[string]bool{}
				for _, v := range logConfig.DoNotLogHeaders {
					result[v] = true
				}
				return result
			}(),
		},
		validate: validate,
		core:     core,
	}, nil
}

// ====================================================================================
// Role Management

// ====================================================================================
// User Management

// ====================================================================================
// Utilities

// -----------------------------------------------------------------------

// Alive godoc
// @Summary User Management API readiness check
// @Description Will return success to indicate user management REST API module is live
// @tags Management
// @Produce json
// @Success 200 {object} StandardResponse "success"
// @Failure 400 {string} string "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} StandardResponse "error"
// @Router /v1/admin/alive [get]
func (h UserManagementHandler) Alive(w http.ResponseWriter, r *http.Request) {
	logTags := h.GetLogTagsForContext(r.Context())
	if err := writeRESTResponse(w, r, http.StatusOK, getStdRESTSuccessMsg(r.Context())); err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to form response")
	}
}

// AliveHandler Wrapper around Alive
func (h UserManagementHandler) AliveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Alive(w, r)
	}
}

// -----------------------------------------------------------------------

// Ready godoc
// @Summary User Management API readiness check
// @Description Will return success if user management REST API module is ready for use
// @tags Management
// @Produce json
// @Success 200 {object} StandardResponse "success"
// @Failure 400 {string} string "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} StandardResponse "error"
// @Router /v1/admin/ready [get]
func (h UserManagementHandler) Ready(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := writeRESTResponse(w, r, respCode, response); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()
	if err := h.core.Ready(); err != nil {
		respCode = http.StatusInternalServerError
		response = getStdRESTErrorMsg(
			r.Context(), http.StatusInternalServerError, "not ready", err.Error(),
		)
	} else {
		respCode = http.StatusOK
		response = getStdRESTSuccessMsg(r.Context())
	}
}

// ReadyHandler Wrapper around Alive
func (h UserManagementHandler) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Ready(w, r)
	}
}
