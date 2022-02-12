package apis

import (
	"fmt"
	"net/http"

	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/models"
	"github.com/alwitt/padlock/users"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
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
			Component: common.Component{LogTags: logTags},
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

// RespListAllRoles is the API response listing all roles the system is operating against
type RespListAllRoles struct {
	BaseResponse
	// Roles are the roles
	Roles map[string]common.UserRoleConfig `json:"roles" validate:"required,dive"`
}

// ListAllRoles godoc
// @Summary List All Roles
// @Description List all roles the system is operating against
// @tags Management
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Success 200 {object} RespListAllRoles "success"
// @Failure 400 {string} string "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} StandardResponse "error"
// @Router /v1/role [get]
func (h UserManagementHandler) ListAllRoles(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := writeRESTResponse(w, r, respCode, response); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()

	roles, err := h.core.ListAllRoles(r.Context())
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to query for all roles in system")
		respCode = http.StatusInternalServerError
		response = getStdRESTErrorMsg(
			r.Context(), http.StatusInternalServerError, "not ready", err.Error(),
		)
	} else {
		respCode = http.StatusOK
		response = RespListAllRoles{
			BaseResponse: getStdRESTSuccessMsg(r.Context()),
			Roles:        roles,
		}
	}
}

// ListAllRolesHandler Wrapper around ListAllRoles
func (h UserManagementHandler) ListAllRolesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.ListAllRoles(w, r)
	}
}

// -----------------------------------------------------------------------

// RespRoleInfo is the API response giving infor on one role
type RespRoleInfo struct {
	BaseResponse
	// Role is info on this role
	Role common.UserRoleConfig `json:"role" validate:"required,dive"`
	// AssignedUsers is the list of users being assigned this role
	AssignedUsers []models.UserInfo `json:"assigned_users,omitempty" validate:"omitempty"`
}

// GetRole godoc
// @Summary Get info on role
// @Description Query for information regarding one role, along with users assigned this role.
// @tags Management
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Param roleName path string true "Role name"
// @Success 200 {object} RespListAllRoles "success"
// @Failure 400 {string} string "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} StandardResponse "error"
// @Router /v1/role/{roleName} [get]
func (h UserManagementHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := writeRESTResponse(w, r, respCode, response); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()

	// Verify the role name is valid
	vars := mux.Vars(r)
	roleName, ok := vars["roleName"]
	if !ok {
		respCode = http.StatusBadRequest
		response = getStdRESTErrorMsg(
			r.Context(),
			http.StatusBadRequest,
			"role name missing",
			"Role name must be provided",
		)
		return
	}
	type testStruct struct {
		Role string `validate:"required,role_name"`
	}
	if err := h.validate.Struct(&testStruct{Role: roleName}); err != nil {
		msg := fmt.Sprintf("role name %s is not valid", roleName)
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = getStdRESTErrorMsg(
			r.Context(), http.StatusBadRequest, msg, err.Error(),
		)
		return
	}

	roleInfo, users, err := h.core.GetRoleWithLinkedUsers(r.Context(), roleName)
	if err != nil {
		msg := fmt.Sprintf("Failed to query for role %s", roleName)
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusInternalServerError
		response = getStdRESTErrorMsg(
			r.Context(), http.StatusInternalServerError, msg, err.Error(),
		)
	} else {
		respCode = http.StatusOK
		response = RespRoleInfo{
			BaseResponse: getStdRESTSuccessMsg(r.Context()), Role: roleInfo, AssignedUsers: users,
		}
	}
}

// GetRoleHandler Wrapper around GetRole
func (h UserManagementHandler) GetRoleHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.GetRole(w, r)
	}
}

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
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Success 200 {object} StandardResponse "success"
// @Failure 400 {string} string "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} StandardResponse "error"
// @Router /v1/alive [get]
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
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Success 200 {object} StandardResponse "success"
// @Failure 400 {string} string "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} StandardResponse "error"
// @Router /v1/ready [get]
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
