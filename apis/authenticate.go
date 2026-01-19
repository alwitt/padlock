// Package apis - application REST API
package apis

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alwitt/goutils"
	"github.com/alwitt/padlock/authenticate"
	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/match"
	"github.com/alwitt/padlock/models"
	"github.com/apex/log"
	"github.com/golang-jwt/jwt/v4"
)

// AuthenticationHandler the request authentication REST API handler
type AuthenticationHandler struct {
	goutils.RestAPIHandler
	oidClient         authenticate.OpenIDIssuerClient
	performIntrospect bool
	introspector      authenticate.Introspector
	targetAudience    *string
	targetClaims      common.OpenIDClaimsOfInterestConfig
	reqHeaderParam    common.AuthenticateRequestParamLocConfig
	respHeaderParam   common.AuthorizeRequestParamLocConfig
	bypassChecker     match.AuthBypassMatch
}

// defineAuthenticationHandler define a new AuthenticationHandler instance
func defineAuthenticationHandler(
	logConfig common.HTTPRequestLogging,
	oid authenticate.OpenIDIssuerClient,
	performIntrospect bool,
	introspector authenticate.Introspector,
	authnCfg common.AuthenticationConfig,
	respHeaderParam common.AuthorizeRequestParamLocConfig,
	metrics goutils.HTTPRequestMetricHelper,
) (AuthenticationHandler, error) {
	logTags := log.Fields{
		"module": "apis", "component": "api-handler", "instance": "authentication",
	}

	instance := AuthenticationHandler{
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
			LogLevel:      logConfig.LogLevel,
			MetricsHelper: metrics,
		},
		oidClient:         oid,
		performIntrospect: performIntrospect,
		introspector:      introspector,
		targetAudience:    authnCfg.TargetAudience,
		targetClaims:      authnCfg.TargetClaims,
		reqHeaderParam:    authnCfg.RequestParamLocation,
		respHeaderParam:   respHeaderParam,
		bypassChecker:     nil,
	}

	if authnCfg.Bypass != nil {
		bypassCheck, err := match.DefineAuthBypassMatch(*authnCfg.Bypass)
		if err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed define authentication bypass matcher")
			return AuthenticationHandler{}, err
		}
		instance.bypassChecker = bypassCheck
	}

	return instance, nil
}

// ====================================================================================
// Authenticate

// Authenticate godoc
// @Summary Authenticate a user
// @Description Authticate a user by verifiying the bearer token provided
// @tags Authenticate
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Param Authorization header string true "User must provide a bearer token"
// @Success 200 {object} goutils.RestAPIBaseResponse "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 401 {string} string "error"
// @Failure 403 {string} string "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/authenticate [get]
func (h AuthenticationHandler) Authenticate(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	respHeaders := map[string]string{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := h.WriteRESTResponse(w, respCode, response, respHeaders); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()

	// Check Bypass rules first
	if h.bypassChecker != nil {
		// Pull request parameters
		t := common.AccessAuthorizeParam{
			Method: r.Header.Get(h.reqHeaderParam.Method),
			Path:   r.Header.Get(h.reqHeaderParam.Path),
			Host:   r.Header.Get(h.reqHeaderParam.Host),
		}
		params := match.RequestParam{Host: &t.Host, Method: t.Method, Path: t.Path}
		matched, err := h.bypassChecker.Match(r.Context(), params)
		if err != nil {
			msg := "authn bypass check failed"
			log.WithError(err).WithFields(logTags).Error(msg)
			respCode = http.StatusBadRequest
			response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
			return
		}
		// Bypass authentication
		if matched {
			respCode = http.StatusOK
			response = h.GetStdRESTSuccessMsg(r.Context())
			return
		}
	}

	errMacroNoErr := func(msg string) {
		log.WithFields(logTags).Error(msg)
		respCode = http.StatusUnauthorized
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusUnauthorized, msg, "")
	}

	// Read the JWT Bearer token
	bearer := r.Header.Get("Authorization")
	if bearer == "" {
		errMacroNoErr("Header 'Authorization' missing")
		return
	}
	bearerParts := strings.Split(bearer, " ")
	if len(bearerParts) != 2 {
		errMacroNoErr("Bearer 'Authorization' has incorrect format")
		return
	}
	rawToken := bearerParts[1]

	errMacro := func(msg string, err error) {
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusUnauthorized
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusUnauthorized, msg, err.Error())
	}

	// Parse the JWT token
	userClaims := new(jwt.MapClaims)
	_, err := h.oidClient.ParseJWT(rawToken, userClaims)
	if err != nil {
		errMacro("Unable to parse JWT bearer token", err)
		return
	}

	{
		t, _ := json.MarshalIndent(userClaims, "", "  ")
		log.WithFields(logTags).Debugf("Token claims\n%s", t)
	}

	fetchClaimAsString := func(target string) (string, error) {
		if v, ok := (*userClaims)[target]; ok {
			if value, ok := v.(string); ok {
				return value, nil
			}
			return "", fmt.Errorf("bearer 'Authorization' token's claim %s is not a string", target)
		}
		return "", fmt.Errorf("bearer 'Authorization' token missing %s", target)
	}

	fetchClaimAsFloat := func(target string) (float64, error) {
		if v, ok := (*userClaims)[target]; ok {
			if value, ok := v.(float64); ok {
				return value, nil
			}
			return 0, fmt.Errorf("bearer 'Authorization' token's claim %s is not a FLOAT64", target)
		}
		return 0, fmt.Errorf("bearer 'Authorization' token missing %s", target)
	}

	// OAuth2 introspect
	if h.performIntrospect {
		if !h.oidClient.CanIntrospect() {
			errMacroNoErr("Missing required settings to perform introspection")
			return
		}
		expirationTime, err := fetchClaimAsFloat("exp")
		if err != nil {
			errMacro("Unable to parse out 'exp' claim", err)
			return
		}
		isValid, err := h.introspector.VerifyToken(
			r.Context(), rawToken, int64(expirationTime), time.Now().UTC(),
		)
		if err != nil {
			errMacro("Introspection process errored", err)
			return
		}
		if !isValid {
			errMacroNoErr("Token no longer active")
			return
		}
	}

	errMacro = func(msg string, err error) {
		log.WithError(err).WithFields(logTags).Error(msg)
		respCode = http.StatusBadRequest
		response = h.GetStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
	}

	// Check "aud" if target audience specified
	if h.targetAudience != nil {
		aud, err := fetchClaimAsString("aud")
		if err != nil {
			errMacro("Unable to parse out 'aud' claim", err)
			return
		}
		// Verify audience matches
		if aud != *h.targetAudience {
			err := fmt.Errorf("'aud' claim does not match expectation")
			errMacro("Invalid token", err)
			return
		}
	}

	// Parse out the critical fields
	userParams := models.UserConfig{}

	// User ID
	uid, err := fetchClaimAsString(h.targetClaims.UserIDClaim)
	if err != nil {
		errMacro(fmt.Sprintf("Unable to parse out '%s' claim", h.targetClaims.UserIDClaim), err)
		return
	}
	userParams.UserID = uid
	respHeaders[h.respHeaderParam.UserID] = uid

	// User name
	if h.targetClaims.UsernameClaim != nil {
		username, err := fetchClaimAsString(*h.targetClaims.UsernameClaim)
		if err != nil {
			errMacro(fmt.Sprintf("Unable to parse out '%s' claim", *h.targetClaims.UsernameClaim), err)
			return
		}
		userParams.Username = &username
		respHeaders[h.respHeaderParam.Username] = username
	}

	// First name
	if h.targetClaims.FirstNameClaim != nil {
		firstName, err := fetchClaimAsString(*h.targetClaims.FirstNameClaim)
		if err != nil {
			errMacro(fmt.Sprintf("Unable to parse out '%s' claim", *h.targetClaims.FirstNameClaim), err)
			return
		}
		userParams.FirstName = &firstName
		respHeaders[h.respHeaderParam.FirstName] = firstName
	}

	// Last name
	if h.targetClaims.LastNameClaim != nil {
		lastName, err := fetchClaimAsString(*h.targetClaims.LastNameClaim)
		if err != nil {
			errMacro(fmt.Sprintf("Unable to parse out '%s' claim", *h.targetClaims.LastNameClaim), err)
			return
		}
		userParams.LastName = &lastName
		respHeaders[h.respHeaderParam.LastName] = lastName
	}

	// Email
	if h.targetClaims.EmailClaim != nil {
		email, err := fetchClaimAsString(*h.targetClaims.EmailClaim)
		if err != nil {
			errMacro(fmt.Sprintf("Unable to parse out '%s' claim", *h.targetClaims.EmailClaim), err)
			return
		}
		userParams.Email = &email
		respHeaders[h.respHeaderParam.Email] = email
	}

	{
		t, _ := json.MarshalIndent(userParams, "", "  ")
		log.WithFields(logTags).Debugf("User parameters in Token\n%s", t)
	}

	// Set the response headers

	respCode = http.StatusOK
	response = h.GetStdRESTSuccessMsg(r.Context())
}

// AuthenticateHandler Wrapper around Authenticate
func (h AuthenticationHandler) AuthenticateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Authenticate(w, r)
	}
}

// ====================================================================================
// Utilities

// AuthenticationLivenessHandler the request authentication REST API liveness handler
type AuthenticationLivenessHandler struct {
	goutils.RestAPIHandler
}

func defineAuthenticationLivenessHandler(
	logConfig common.HTTPRequestLogging,
) AuthenticationLivenessHandler {
	logTags := log.Fields{
		"module": "apis", "component": "api-handler", "instance": "authentication-liveness",
	}

	return AuthenticationLivenessHandler{
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
			LogLevel: logConfig.HealthLogLevel,
		},
	}
}

// Alive godoc
// @Summary Authentication API liveness check
// @Description Will return success to indicate Authentication REST API module is live
// @tags Authenticate
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Success 200 {object} goutils.RestAPIBaseResponse "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/alive [get]
func (h AuthenticationLivenessHandler) Alive(w http.ResponseWriter, r *http.Request) {
	logTags := h.GetLogTagsForContext(r.Context())
	if err := h.WriteRESTResponse(
		w, http.StatusOK, h.GetStdRESTSuccessMsg(r.Context()), nil,
	); err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to form response")
	}
}

// AliveHandler Wrapper around Alive
func (h AuthenticationLivenessHandler) AliveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Alive(w, r)
	}
}

// -----------------------------------------------------------------------

// Ready godoc
// @Summary Authentication API readiness check
// @Description Will return success if Authentication REST API module is ready for use
// @tags Authenticate
// @Produce json
// @Param Padlock-Request-ID header string false "User provided request ID to match against logs"
// @Success 200 {object} goutils.RestAPIBaseResponse "success"
// @Failure 400 {object} goutils.RestAPIBaseResponse "error"
// @Failure 404 {string} string "error"
// @Failure 500 {object} goutils.RestAPIBaseResponse "error"
// @Router /v1/ready [get]
func (h AuthenticationLivenessHandler) Ready(w http.ResponseWriter, r *http.Request) {
	var respCode int
	var response interface{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := h.WriteRESTResponse(w, respCode, response, nil); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()
	respCode = http.StatusOK
	response = h.GetStdRESTSuccessMsg(r.Context())
}

// ReadyHandler Wrapper around Alive
func (h AuthenticationLivenessHandler) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Ready(w, r)
	}
}
