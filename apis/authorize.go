package apis

import (
	"context"
	"fmt"
	"net/http"

	"github.com/alwitt/goutils"
	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/match"
	"github.com/alwitt/padlock/models"
	"github.com/alwitt/padlock/users"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
)

// AuthorizationHandler the request authorization REST API handler
type AuthorizationHandler struct {
	goutils.RestAPIHandler
	validate       *validator.Validate
	core           users.Management
	checkHeaders   common.AuthorizeRequestParamLocConfig
	forUnknown     common.UnknownUserActionConfig
	requestMatcher match.RequestMatch
}

// defineAuthorizationHandler define a new AuthorizationHandler instance
func defineAuthorizationHandler(
	logConfig common.HTTPRequestLogging,
	core users.Management,
	matcher match.RequestMatch,
	validateSupport common.CustomFieldValidator,
	checkHeaders common.AuthorizeRequestParamLocConfig,
	forUnknownUser common.UnknownUserActionConfig,
	metrics goutils.HTTPRequestMetricHelper,
) (AuthorizationHandler, error) {
	validate := validator.New()
	if err := validateSupport.RegisterWithValidator(validate); err != nil {
		return AuthorizationHandler{}, err
	}

	logTags := log.Fields{
		"module": "apis", "component": "api-handler", "instance": "authorization",
	}

	return AuthorizationHandler{
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
			LogLevel:      logConfig.LogLevel,
			MetricsHelper: metrics,
		},
		validate:       validate,
		core:           core,
		checkHeaders:   checkHeaders,
		forUnknown:     forUnknownUser,
		requestMatcher: matcher,
	}, nil
}

/*
ParamReadMiddleware is a support middleware to be used with Mux to extract the mandatory
parameters needed to authorize a REST API call and record it in the context.

	@param next http.HandlerFunc - the core request handler function
	@return middleware http.HandlerFunc
*/
func (h AuthorizationHandler) ParamReadMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		params := common.AccessAuthorizeParam{
			UserID: r.Header.Get(h.checkHeaders.UserID),
			Method: r.Header.Get(h.checkHeaders.Method),
			Path:   r.Header.Get(h.checkHeaders.Path),
			Host:   r.Header.Get(h.checkHeaders.Host),
		}
		ctxt := context.WithValue(r.Context(), common.AccessAuthorizeParamKey{}, params)
		next(rw, r.WithContext(ctxt))
	}
}

// ====================================================================================
// Authorization

// Allow godoc
// @Summary Check whether a REST API call is allowed
// @Description Check whether a REST API call is allowed. The parameters of the call is passed in
// via HTTP headers by the entity using this endpoint. The parameters listed in this comment
// section are the default headers the application will search for. But the headers to check
// can be configured via the "authorize.request_param_location" object of the application config.
// @tags Authorize
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Param X-Forwarded-Host header string true "Host of the API call to authorize"
// @Param X-Forwarded-Uri header string true "URI path of the API call to authorize"
// @Param X-Forwarded-Method header string true "HTTP method of the API call to authorize"
// @Param X-Caller-UserID header string true "ID of the user making the API call to authorize"
// @Param X-Caller-Username header string false "Username of the user making the API call to authorize"
// @Param X-Caller-Firstname header string false "First name / given name of the user making the API call to authorize"
// @Param X-Caller-Lastname header string false "Last name / surname / family name of the user making the API call to authorize"
// @Param X-Caller-Email header string false "Email of the user making the API call to authorize"
// @Success 200 {object} goutils.RestAPIBaseResponse "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 403 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/allow [get]
func (h AuthorizationHandler) Allow(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := h.WriteRESTResponse(w, respCode, response, nil); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()

	// Fetch the parameters of the request being authorized
	if r.Context().Value(common.AccessAuthorizeParamKey{}) == nil {
		msg := "can't run authorization check"
		err := fmt.Errorf("missing parameter regarding REST API call to authorize")
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}

	// Fetch the manditory parameters regarding REST request to authorize
	params, ok := r.Context().Value(common.AccessAuthorizeParamKey{}).(common.AccessAuthorizeParam)
	if !ok {
		msg := "can't run authorization check"
		err := fmt.Errorf("AuthorizationHandler.paramReadMiddleware() malfunction")
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusInternalServerError
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusInternalServerError, msg, err.Error())
		return
	}
	if err := h.validate.Struct(&params); err != nil {
		msg := "Manditory parameters for REST request to authorize not valid"
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}

	// Get the absolute path of the request
	reqAbsPath, err := match.GetAbsPath(params.Path)
	if err != nil {
		msg := "Request path normalization failed"
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}

	logTags["auth_abs_path"] = reqAbsPath

	// Determine the accepted permissions to trigger the REST API with method
	allowedPermissions, err := h.requestMatcher.Match(r.Context(), match.RequestParam{
		Host: &params.Host, Path: reqAbsPath, Method: params.Method,
	})
	if err != nil {
		msg := fmt.Sprintf(
			"Unable to find match for '%s' against defined API authorizations", params.String(),
		)
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
		return
	}

	// Check whether the user is allowed to trigger the REST API with method
	allowed, err := h.core.DoesUserHavePermission(r.Context(), params.UserID, allowedPermissions)
	if err == nil {
		// User is known
		if allowed {
			respCode = http.StatusOK
			response = h.GetStdRESTSuccessMsg(r.Context())
		} else {
			msg := fmt.Sprintf("User ID %s not allow to '%s'", params.UserID, params.String())
			log.WithFields(logTags).Error(msg)
			respCode = http.StatusForbidden
			response = h.GetStdRESTErrorMsg(r.Context(), http.StatusForbidden, msg, "")
		}
	} else {
		// This user is not known
		if h.forUnknown.AutoAdd {
			// Automatically register the user with the system
			// Fetch the optional parameters regarding REST request to authorize
			username := r.Header.Get(h.checkHeaders.Username)
			userEmail := r.Header.Get(h.checkHeaders.Email)
			firstName := r.Header.Get(h.checkHeaders.FirstName)
			lastName := r.Header.Get(h.checkHeaders.LastName)
			// Define the new user
			newUserParams := models.UserConfig{UserID: params.UserID}
			if username != "" {
				newUserParams.Username = &username
			}
			if userEmail != "" {
				newUserParams.Email = &userEmail
			}
			if firstName != "" {
				newUserParams.FirstName = &firstName
			}
			if lastName != "" {
				newUserParams.LastName = &lastName
			}
			log.WithFields(logTags).Debugf("Recording new user ID %s", params.UserID)
			if err := h.core.DefineUser(r.Context(), newUserParams, nil); err != nil {
				msg := fmt.Sprintf("Failed to record user ID %s", params.UserID)
				log.WithError(err).WithFields(logTags).Error(msg)
				respCode = http.StatusInternalServerError
				response = h.GetStdRESTErrorMsg(
					r.Context(), http.StatusInternalServerError, msg, err.Error(),
				)
			} else {
				msg := fmt.Sprintf("Recorded new user ID %s with no permissions", params.UserID)
				log.WithFields(logTags).Error(msg)
				respCode = http.StatusForbidden
				response = h.GetStdRESTErrorMsg(r.Context(), http.StatusForbidden, msg, "")
			}
		} else {
			// User must be manually registered with the system
			msg := fmt.Sprintf("User ID %s is unknown", params.UserID)
			log.WithFields(logTags).Error(msg)
			respCode = http.StatusForbidden
			response = h.GetStdRESTErrorMsg(r.Context(), http.StatusForbidden, msg, "")
		}
	}
}

// AllowHandler Wrapper around Allow
func (h AuthorizationHandler) AllowHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Allow(w, r)
	}
}

// ====================================================================================
// Utilities

// AuthorizationLivenessHandler the request authorization REST API liveness handler
type AuthorizationLivenessHandler struct {
	goutils.RestAPIHandler
	core users.Management
}

func defineAuthorizationLivenessHandler(
	logConfig common.HTTPRequestLogging, core users.Management,
) AuthorizationLivenessHandler {
	logTags := log.Fields{
		"module": "apis", "component": "api-handler", "instance": "authorization-liveness",
	}

	return AuthorizationLivenessHandler{
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
// @Summary Authorization API liveness check
// @Description Will return success to indicate authorization REST API module is live
// @tags Authorize
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Success 200 {object} goutils.RestAPIBaseResponse "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/alive [get]
func (h AuthorizationLivenessHandler) Alive(w http.ResponseWriter, r *http.Request) {
	logTags := h.GetLogTagsForContext(r.Context())
	if err := h.WriteRESTResponse(
		w, http.StatusOK, h.GetStdRESTSuccessMsg(r.Context()), nil,
	); err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to form response")
	}
}

// AliveHandler Wrapper around Alive
func (h AuthorizationLivenessHandler) AliveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Alive(w, r)
	}
}

// -----------------------------------------------------------------------

// Ready godoc
// @Summary Authorization API readiness check
// @Description Will return success if authorization REST API module is ready for use
// @tags Authorize
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Success 200 {object} goutils.RestAPIBaseResponse "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/ready [get]
func (h AuthorizationLivenessHandler) Ready(w http.ResponseWriter, r *http.Request) {
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
func (h AuthorizationLivenessHandler) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Ready(w, r)
	}
}
