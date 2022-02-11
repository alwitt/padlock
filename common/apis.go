package common

import (
	"fmt"
	"net/http"
	"time"

	"github.com/apex/log"
)

// AccessAuthorizeParamKey associated key for AccessAuthorizeParam when storing in request context
type AccessAuthorizeParamKey struct{}

// AccessAuthorizeParam contains the authorization request parameters, stored in request context
type AccessAuthorizeParam struct {
	// UserID is the ID of the user needing access
	UserID string `json:"user_id" validate:"required,user_id"`
	// Method is the method used
	Method string `json:"method" validate:"required,oneof=GET HEAD PUT POST PATCH DELETE OPTIONS"`
	// Path is the request Path needing access check
	Path string `json:"path" validate:"required,uri"`
	// Host is the Host needing access check
	Host string `json:"host" validate:"required,fqdn"`
}

// updateLogTags updates Apex log.Fields map with values from the parameter
func (i *AccessAuthorizeParam) updateLogTags(tags log.Fields) {
	tags["auth_user_id"] = i.UserID
	tags["auth_method"] = i.Method
	tags["auth_path"] = fmt.Sprintf("'%s'", i.Path)
	tags["auth_host"] = i.Host
}

// RequestParamKey associated key for RequestParam when storing in request context
type RequestParamKey struct{}

// RequestParam is a helper object for logging a request's parameters into its context
type RequestParam struct {
	// ID is the request ID
	ID string `json:"id"`
	// Host is the request host
	Host string `json:"host" validate:"required,fqdn"`
	// URI is the request URI
	URI string `json:"uri" validate:"required,uri"`
	// Method is the request method
	Method string `json:"method" validate:"required,oneof=GET HEAD PUT POST PATCH DELETE OPTIONS"`
	// Referer is the request referer string
	Referer string `json:"referer"`
	// RemoteAddr is the request
	RemoteAddr string `json:"remote_address"`
	// Proto is the request HTTP proto string
	Proto string `json:"http_proto"`
	// ProtoMajor is the request HTTP proto major version
	ProtoMajor int `json:"http_version_major"`
	// ProtoMinor is the request HTTP proto minor version
	ProtoMinor int `json:"http_version_minor"`
	// RequestHeaders additional request headers
	RequestHeaders http.Header
	// Timestamp is when the request is first received
	Timestamp time.Time
}

// updateLogTags updates Apex log.Fields map with values the requests's parameters
func (i *RequestParam) updateLogTags(tags log.Fields) {
	tags["request_id"] = i.ID
	tags["request_host"] = i.Host
	tags["request_uri"] = fmt.Sprintf("'%s'", i.URI)
	tags["request_method"] = i.Method
	tags["request_referer"] = i.Referer
	tags["request_remote_address"] = i.RemoteAddr
	tags["request_proto"] = i.Proto
	tags["request_http_version_major"] = i.ProtoMajor
	tags["request_http_version_minor"] = i.ProtoMinor
	tags["request_timestamp"] = i.Timestamp.UTC().Format(time.RFC3339Nano)
	for header, headerValues := range i.RequestHeaders {
		tags[header] = headerValues
	}
}
