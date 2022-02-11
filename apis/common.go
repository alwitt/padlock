package apis

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/alwitt/padlock/common"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// ErrorDetail is the response detail in case of error
type ErrorDetail struct {
	// Code is the response code
	Code int `json:"code" validate:"required"`
	// Msg is an optional descriptive message
	Msg string `json:"message,omitempty"`
	// Detail is an optional descriptive message providing additional details on the error
	Detail string `json:"detail,omitempty"`
}

// BaseResponse standard REST API response
type BaseResponse struct {
	// Success indicates whether the request was successful
	Success bool `json:"success" validate:"required"`
	// RequestID gives the request ID to match against logs
	RequestID string `json:"request_id" validate:"required"`
	// Error are details in case of errors
	Error *ErrorDetail `json:"error,omitempty"`
}

// readRequestIDFromContext reads the request ID from the request context if available
func readRequestIDFromContext(ctxt context.Context) string {
	if ctxt.Value(common.RequestParamKey{}) != nil {
		v, ok := ctxt.Value(common.RequestParamKey{}).(common.RequestParam)
		if ok {
			return v.ID
		}
	}
	return ""
}

// getStdRESTSuccessMsg defines a standard success message
func getStdRESTSuccessMsg(ctxt context.Context) BaseResponse {
	return BaseResponse{Success: true, RequestID: readRequestIDFromContext(ctxt)}
}

// getStdRESTErrorMsg defines a standard error message
func getStdRESTErrorMsg(
	ctxt context.Context, code int, message string, detail string,
) BaseResponse {
	return BaseResponse{
		Success:   false,
		RequestID: readRequestIDFromContext(ctxt),
		Error:     &ErrorDetail{Code: code, Msg: message, Detail: detail},
	}
}

// writeRESTResponse writes a REST response
func writeRESTResponse(
	w http.ResponseWriter, r *http.Request, respCode int, resp interface{},
) error {
	w.Header().Set("content-type", "application/json")
	if r.Context().Value(common.RequestParamKey{}) != nil {
		v, ok := r.Context().Value(common.RequestParamKey{}).(common.RequestParam)
		if ok {
			w.Header().Add("Padlock-Request-ID", v.ID)
		}
	}
	w.WriteHeader(respCode)
	t, err := json.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}
	if _, err = w.Write(t); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}
	return nil
}

// ========================================================================================

// MethodHandlers DICT of method-endpoint handler
type MethodHandlers map[string]http.HandlerFunc

// registerPathPrefix registers new method handler for a path prefix
func registerPathPrefix(parent *mux.Router, prefix string, handler MethodHandlers) *mux.Router {
	router := parent.PathPrefix(prefix).Subrouter()
	for method, handler := range handler {
		router.Methods(method).Path("").HandlerFunc(handler)
	}
	return router
}

// APIRestHandler base REST handler
type APIRestHandler struct {
	common.Component
	endOfRequestLog       string
	offLimitHeadersForLog map[string]bool
}

/*
LoggingMiddleware is a support middleware to be used with Mux to perform request logging

 @param next http.HandlerFunc - the core request handler function
 @return middleware http.HandlerFunc
*/
func (h APIRestHandler) LoggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		// use provided request id from incoming request if any
		reqID := r.Header.Get("Padlock-Request-ID")
		if reqID == "" {
			// or use some generated string
			reqID = uuid.New().String()
		}
		// Construct the request param tracking structure
		params := common.RequestParam{
			ID:             reqID,
			Host:           r.Host,
			URI:            r.URL.String(),
			Method:         r.Method,
			Referer:        r.Referer(),
			RemoteAddr:     r.RemoteAddr,
			Proto:          r.Proto,
			ProtoMajor:     r.ProtoMajor,
			ProtoMinor:     r.ProtoMinor,
			Timestamp:      time.Now(),
			RequestHeaders: make(http.Header),
		}
		// File in the request headers
		for headerField, headerValues := range r.Header {
			if _, present := h.offLimitHeadersForLog[headerField]; !present {
				params.RequestHeaders[headerField] = headerValues
			}
		}
		// Construct new context
		ctxt := context.WithValue(r.Context(), common.RequestParamKey{}, params)
		// Make the request
		respRecorder := httptest.NewRecorder()
		next(respRecorder, r.WithContext(ctxt))
		respTimestamp := time.Now()
		// Log result of request
		logTags := h.GetLogTagsForContext(ctxt)
		log.WithFields(logTags).
			WithField("response_code", respRecorder.Code).
			WithField("response_size", respRecorder.Body.Len()).
			WithField("response_timestamp", respTimestamp.UTC().Format(time.RFC3339Nano)).
			Warn(h.endOfRequestLog)
		// Copy the recorded response to the response writer
		for k, v := range respRecorder.Header() {
			rw.Header()[k] = v
		}
		rw.WriteHeader(respRecorder.Code)
		if _, err := respRecorder.Body.WriteTo(rw); err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Failed to transfer response to actual writer")
		}
	}
}
