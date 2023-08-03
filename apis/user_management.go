package apis

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/alwitt/goutils"
	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/models"
	"github.com/alwitt/padlock/users"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
)

// UserManagementHandler the user / role management REST API handler
type UserManagementHandler struct {
	goutils.RestAPIHandler
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
		RestAPIHandler: goutils.RestAPIHandler{
			Component: goutils.Component{
				LogTags: logTags,
				LogTagModifiers: []goutils.LogMetadataModifier{
					goutils.ModifyLogMetadataByRestRequestParam,
				},
			},
			CallRequestIDHeaderField: &logConfig.RequestIDHeader,
			DoNotLogHeaders: func() map[string]bool {
				result := map[string]bool{}
				for _, v := range logConfig.DoNotLogHeaders {
					result[v] = true
				}
				return result
			}(),
			LogLevel: logConfig.LogLevel,
		},
		validate: validate,
		core:     core,
	}, nil
}

// ====================================================================================
// Role Management

// RespListAllRoles is the API response listing all roles the system is operating against
type RespListAllRoles struct {
	goutils.RestAPIBaseResponse
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
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/role [get]
func (h UserManagementHandler) ListAllRoles(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := h.WriteRESTResponse(w, respCode, response, nil); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()

	roles, err := h.core.ListAllRoles(r.Context())
	if err != nil {
		msg := "Failed to query for all roles in system"
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusInternalServerError
		response = h.GetStdRESTErrorMsg(
			r.Context(), http.StatusInternalServerError, msg, err.Error(),
		)
	} else {
		respCode = http.StatusOK
		response = RespListAllRoles{
			RestAPIBaseResponse: h.GetStdRESTSuccessMsg(r.Context()), Roles: roles,
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

// RespRoleInfo is the API response giving info on one role
type RespRoleInfo struct {
	goutils.RestAPIBaseResponse
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
// @Success 200 {object} RespRoleInfo "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/role/{roleName} [get]
func (h UserManagementHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := h.WriteRESTResponse(w, respCode, response, nil); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()

	// Verify the role name is valid
	vars := mux.Vars(r)
	roleName, ok := vars["roleName"]
	if !ok {
		log.WithFields(logTags).Errorf("Role name missing")
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(
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
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}

	roleInfo, users, err := h.core.GetRoleWithLinkedUsers(r.Context(), roleName)
	if err != nil {
		msg := fmt.Sprintf("Failed to query for role %s", roleName)
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusInternalServerError
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusInternalServerError, msg, err.Error())
	} else {
		respCode = http.StatusOK
		response = RespRoleInfo{
			RestAPIBaseResponse: h.GetStdRESTSuccessMsg(r.Context()),
			Role:                roleInfo,
			AssignedUsers:       users,
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

// ReqNewUserParams is the API request with information on a new user
type ReqNewUserParams struct {
	// User contains the new user parameters
	User models.UserConfig `json:"user" validate:"required,dive"`
	// Roles list the roles to assign to this user
	Roles []string `json:"roles" validate:"omitempty,dive,role_name"`
}

// DefineUser godoc
// @Summary Define new user
// @Description Define a new user, and optionally assign roles to it
// @tags Management
// @Accept json
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Param userInfo body ReqNewUserParams true "New user information"
// @Success 200 {object} goutils.RestAPIBaseResponse "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/user [post]
func (h UserManagementHandler) DefineUser(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := h.WriteRESTResponse(w, respCode, response, nil); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()

	var userInfo ReqNewUserParams
	if err := json.NewDecoder(r.Body).Decode(&userInfo); err != nil {
		msg := "new user parameters not parsable"
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}
	if err := h.validate.Struct(&userInfo); err != nil {
		msg := "new user parameters not valid"
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}

	if err := h.core.DefineUser(r.Context(), userInfo.User, userInfo.Roles); err != nil {
		msg := fmt.Sprintf("Failed to define new user %s", userInfo.User.UserID)
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusInternalServerError
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusInternalServerError, msg, err.Error())
	} else {
		respCode = http.StatusOK
		response = h.GetStdRESTSuccessMsg(r.Context())
	}
}

// DefineUserHandler Wrapper around DefineUser
func (h UserManagementHandler) DefineUserHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.DefineUser(w, r)
	}
}

// -----------------------------------------------------------------------

// RespListAllUsers is the API response listing all the users the system is managing
type RespListAllUsers struct {
	goutils.RestAPIBaseResponse
	// Users are the users in system
	Users []models.UserInfo `json:"users" validate:"required,dive"`
}

// ListAllUsers godoc
// @Summary List all users
// @Description List all users currently managed by the system
// @tags Management
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Success 200 {object} RespListAllUsers "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/user [get]
func (h UserManagementHandler) ListAllUsers(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := h.WriteRESTResponse(w, respCode, response, nil); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()

	users, err := h.core.ListAllUsers(r.Context())
	if err != nil {
		msg := "Failed to query for all users in system"
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusInternalServerError
		response = h.GetStdRESTErrorMsg(
			r.Context(), http.StatusInternalServerError, msg, err.Error(),
		)
	} else {
		respCode = http.StatusOK
		response = RespListAllUsers{
			RestAPIBaseResponse: h.GetStdRESTSuccessMsg(r.Context()), Users: users,
		}
	}
}

// ListAllUsersHandler Wrapper around ListAllUsers
func (h UserManagementHandler) ListAllUsersHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.ListAllUsers(w, r)
	}
}

// -----------------------------------------------------------------------

// fetchUserID helper function to fetch the user ID from URI path
func (h UserManagementHandler) fetchUserID(r *http.Request) (string, error) {
	vars := mux.Vars(r)
	userID, ok := vars["userID"]
	if !ok {
		return "", fmt.Errorf("missing user ID in URI path")
	}
	type testStruct struct {
		UserID string `validate:"required,user_id"`
	}
	if err := h.validate.Struct(&testStruct{UserID: userID}); err != nil {
		return "", err
	}
	return userID, nil
}

// RespUserInfo is the API response giving info on one user
type RespUserInfo struct {
	goutils.RestAPIBaseResponse
	// User is info on this user
	User users.UserDetailsWithPermission `json:"user" validate:"required,dive"`
}

// GetUser godoc
// @Summary Get info on user
// @Description Query for information regarding one user.
// @tags Management
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Param userID path string true "User ID"
// @Success 200 {object} RespUserInfo "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/user/{userID} [get]
func (h UserManagementHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := h.WriteRESTResponse(w, respCode, response, nil); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()

	// Get user ID
	userID, err := h.fetchUserID(r)
	if err != nil {
		msg := "no valid user ID"
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}

	userInfo, err := h.core.GetUser(r.Context(), userID)
	if err != nil {
		msg := fmt.Sprintf("Failed to query for user %s", userID)
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusInternalServerError
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusInternalServerError, msg, err.Error())
	} else {
		respCode = http.StatusOK
		response = RespUserInfo{
			RestAPIBaseResponse: h.GetStdRESTSuccessMsg(r.Context()), User: userInfo,
		}
	}
}

// GetUserHandler Wrapper around GetUser
func (h UserManagementHandler) GetUserHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.GetUser(w, r)
	}
}

// -----------------------------------------------------------------------

// DeleteUser godoc
// @Summary Delete user
// @Description Remove user from the system.
// @tags Management
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Param userID path string true "User ID"
// @Success 200 {object} goutils.RestAPIBaseResponse "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/user/{userID} [delete]
func (h UserManagementHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := h.WriteRESTResponse(w, respCode, response, nil); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()

	// Get user ID
	userID, err := h.fetchUserID(r)
	if err != nil {
		msg := "no valid user ID"
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}

	if err := h.core.DeleteUser(r.Context(), userID); err != nil {
		msg := fmt.Sprintf("Failed to delete user %s", userID)
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusInternalServerError
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusInternalServerError, msg, err.Error())
	} else {
		respCode = http.StatusOK
		response = h.GetStdRESTSuccessMsg(r.Context())
	}
}

// DeleteUserHandler Wrapper around DeleteUser
func (h UserManagementHandler) DeleteUserHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.DeleteUser(w, r)
	}
}

// -----------------------------------------------------------------------

// UpdateUser godoc
// @Summary Update a user's info
// @Description Update an existing user's information
// @tags Management
// @Accept json
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Param userID path string true "User ID"
// @Param userInfo body models.UserConfig true "Updated user information"
// @Success 200 {object} goutils.RestAPIBaseResponse "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/user/{userID} [put]
func (h UserManagementHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := h.WriteRESTResponse(w, respCode, response, nil); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()

	// Get user ID
	userID, err := h.fetchUserID(r)
	if err != nil {
		msg := "no valid user ID"
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}

	var userInfo models.UserConfig
	if err := json.NewDecoder(r.Body).Decode(&userInfo); err != nil {
		msg := "user parameters not parsable"
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}
	if err := h.validate.Struct(&userInfo); err != nil {
		msg := "user parameters not valid"
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}

	if err := h.core.UpdateUser(r.Context(), userID, userInfo); err != nil {
		msg := fmt.Sprintf("Failed to update user %s", userID)
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusInternalServerError
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusInternalServerError, msg, err.Error())
	} else {
		respCode = http.StatusOK
		response = h.GetStdRESTSuccessMsg(r.Context())
	}
}

// UpdateUserHandler Wrapper around UpdateUser
func (h UserManagementHandler) UpdateUserHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.UpdateUser(w, r)
	}
}

// -----------------------------------------------------------------------

// ReqNewUserRoles is the new roles to be assigned to the user
type ReqNewUserRoles struct {
	// Roles list the roles to assign to this user
	Roles []string `json:"roles" validate:"omitempty,dive,role_name"`
}

// UpdateUserRoles godoc
// @Summary Update a user's roles
// @Description Change the user's roles to what caller requested
// @tags Management
// @Accept json
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Param userID path string true "User ID"
// @Param roles body ReqNewUserRoles true "User's new roles"
// @Success 200 {object} goutils.RestAPIBaseResponse "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/user/{userID}/roles [put]
func (h UserManagementHandler) UpdateUserRoles(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := h.WriteRESTResponse(w, respCode, response, nil); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()

	// Get user ID
	userID, err := h.fetchUserID(r)
	if err != nil {
		msg := "no valid user ID"
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}

	var newRoles ReqNewUserRoles
	if err := json.NewDecoder(r.Body).Decode(&newRoles); err != nil {
		msg := "new role parameters not parsable"
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}
	if err := h.validate.Struct(&newRoles); err != nil {
		msg := "new role parameters not valid"
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}

	if err := h.core.SetUserRoles(r.Context(), userID, newRoles.Roles); err != nil {
		msg := fmt.Sprintf("Failed to set user %s roles", userID)
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusInternalServerError
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusInternalServerError, msg, err.Error())
	} else {
		respCode = http.StatusOK
		response = h.GetStdRESTSuccessMsg(r.Context())
	}
}

// UpdateUserRolesHandler Wrapper around UpdateUserRoles
func (h UserManagementHandler) UpdateUserRolesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.UpdateUserRoles(w, r)
	}
}

// ====================================================================================
// Utilities

// UserManagementLivenessHandler the user / role management REST API liveness handler
type UserManagementLivenessHandler struct {
	goutils.RestAPIHandler
	core users.Management
}

func defineUserManagementLivenessHandler(
	logConfig common.HTTPRequestLogging,
	core users.Management,
) UserManagementLivenessHandler {
	logTags := log.Fields{
		"module": "apis", "component": "api-handler", "instance": "user-management-liveness",
	}

	return UserManagementLivenessHandler{
		RestAPIHandler: goutils.RestAPIHandler{
			Component: goutils.Component{
				LogTags: logTags,
				LogTagModifiers: []goutils.LogMetadataModifier{
					goutils.ModifyLogMetadataByRestRequestParam,
					common.ModifyLogMetadataByAccessAuthorizeParam,
				},
			},
			CallRequestIDHeaderField: &logConfig.RequestIDHeader,
			DoNotLogHeaders: func() map[string]bool {
				result := map[string]bool{}
				for _, v := range logConfig.DoNotLogHeaders {
					result[v] = true
				}
				return result
			}(),
			LogLevel: logConfig.HealthLogLevel,
		}, core: core,
	}
}

// Alive godoc
// @Summary User Management API liveness check
// @Description Will return success to indicate user management REST API module is live
// @tags Management
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Success 200 {object} goutils.RestAPIBaseResponse "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/alive [get]
func (h UserManagementLivenessHandler) Alive(w http.ResponseWriter, r *http.Request) {
	logTags := h.GetLogTagsForContext(r.Context())
	if err := h.WriteRESTResponse(
		w, http.StatusOK, h.GetStdRESTSuccessMsg(r.Context()), nil,
	); err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to form response")
	}
}

// AliveHandler Wrapper around Alive
func (h UserManagementLivenessHandler) AliveHandler() http.HandlerFunc {
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
// @Success 200 {object} goutils.RestAPIBaseResponse "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/ready [get]
func (h UserManagementLivenessHandler) Ready(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := h.WriteRESTResponse(w, respCode, response, nil); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()
	if err := h.core.Ready(); err != nil {
		respCode = http.StatusInternalServerError
		response = h.GetStdRESTErrorMsg(
			r.Context(), http.StatusInternalServerError, "not ready", err.Error(),
		)
	} else {
		respCode = http.StatusOK
		response = h.GetStdRESTSuccessMsg(r.Context())
	}
}

// ReadyHandler Wrapper around Alive
func (h UserManagementLivenessHandler) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Ready(w, r)
	}
}
