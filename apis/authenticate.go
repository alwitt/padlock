package apis

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/alwitt/padlock/authenticate"
	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/models"
	"github.com/apex/log"
	"github.com/golang-jwt/jwt"
)

// AuthenticationHandler the request authentication REST API handler
type AuthenticationHandler struct {
	APIRestHandler
	oidClient       authenticate.OpenIDIssuerClient
	targetClaims    common.OpenIDClaimsOfInterestConfig
	respHeaderParam common.AuthorizeRequestParamLocConfig
}

// defineAuthenticationHandler define a new AuthenticationHandler instance
func defineAuthenticationHandler(
	logConfig common.HTTPRequestLogging,
	oid authenticate.OpenIDIssuerClient,
	targetClaims common.OpenIDClaimsOfInterestConfig,
	respHeaderParam common.AuthorizeRequestParamLocConfig,
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
		}, oidClient: oid, targetClaims: targetClaims, respHeaderParam: respHeaderParam,
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
	var respCode int
	var response interface{}
	respHeaders := map[string]string{}
	logTags := h.GetLogTagsForContext(r.Context())
	defer func() {
		if err := writeRESTResponse(w, r, respCode, response, respHeaders); err != nil {
			log.WithError(err).WithFields(logTags).Error("Failed to form response")
		}
	}()

	// Read the JWT Bearer token
	bearer := r.Header.Get("Authorization")
	if bearer == "" {
		msg := "Header 'Authorization' missing"
		log.WithFields(logTags).Errorf(msg)
		respCode = http.StatusBadRequest
		response = getStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, "")
		return
	}
	bearerParts := strings.Split(bearer, " ")
	if len(bearerParts) != 2 {
		msg := "Bearer 'Authorization' has incorrect format"
		log.WithFields(logTags).Errorf(msg)
		respCode = http.StatusBadRequest
		response = getStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, "")
		return
	}
	rawToken := bearerParts[1]

	// Parse the JWT token
	userClaims := new(jwt.MapClaims)
	_, err := h.oidClient.ParseJWT(rawToken, userClaims)
	if err != nil {
		msg := "Unable to parse JWT bearer token"
		log.WithError(err).WithFields(logTags).Errorf(msg)
		respCode = http.StatusBadRequest
		response = getStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
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

	errMacro := func(msg string, err error) {
		log.WithError(err).WithFields(logTags).Errorf(msg)
		respCode = http.StatusBadRequest
		response = getStdRESTErrorMsg(r.Context(), http.StatusBadRequest, msg, err.Error())
	}

	// Parse out the critical fields
	userParams := models.UserConfig{}

	// Token ID
	tokenID, err := fetchClaimAsString("jti")
	if err != nil {
		errMacro("Unable to parse out 'jti'", err)
		return
	}

	// User ID
	uid, err := fetchClaimAsString(h.targetClaims.UserIDClaim)
	if err != nil {
		errMacro(fmt.Sprintf("Unable to parse out '%s'", h.targetClaims.UserIDClaim), err)
		return
	}
	userParams.UserID = uid
	respHeaders[h.respHeaderParam.UserID] = uid

	// User name
	if h.targetClaims.UsernameClaim != nil {
		username, err := fetchClaimAsString(*h.targetClaims.UsernameClaim)
		if err != nil {
			errMacro(fmt.Sprintf("Unable to parse out '%s'", *h.targetClaims.UsernameClaim), err)
			return
		}
		userParams.Username = &username
		respHeaders[h.respHeaderParam.Username] = username
	}

	// First name
	if h.targetClaims.FirstNameClaim != nil {
		firstName, err := fetchClaimAsString(*h.targetClaims.FirstNameClaim)
		if err != nil {
			errMacro(fmt.Sprintf("Unable to parse out '%s'", *h.targetClaims.FirstNameClaim), err)
			return
		}
		userParams.FirstName = &firstName
		respHeaders[h.respHeaderParam.FirstName] = firstName
	}

	// Last name
	if h.targetClaims.LastNameClaim != nil {
		lastName, err := fetchClaimAsString(*h.targetClaims.LastNameClaim)
		if err != nil {
			errMacro(fmt.Sprintf("Unable to parse out '%s'", *h.targetClaims.LastNameClaim), err)
			return
		}
		userParams.LastName = &lastName
		respHeaders[h.respHeaderParam.LastName] = lastName
	}

	// Email
	if h.targetClaims.EmailClaim != nil {
		email, err := fetchClaimAsString(*h.targetClaims.EmailClaim)
		if err != nil {
			errMacro(fmt.Sprintf("Unable to parse out '%s'", *h.targetClaims.EmailClaim), err)
			return
		}
		userParams.Email = &email
		respHeaders[h.respHeaderParam.Email] = email
	}

	{
		t, _ := json.MarshalIndent(userParams, "", "  ")
		log.WithFields(logTags).Debugf("User parameters in Token %s\n%s", tokenID, t)
	}

	// Set the response headers

	respCode = http.StatusOK
	response = getStdRESTSuccessMsg(r.Context())
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
