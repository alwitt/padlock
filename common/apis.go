package common

import (
	"context"
	"fmt"

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

// String implements toString for object
func (i *AccessAuthorizeParam) String() string {
	return fmt.Sprintf("%s http://%s%s", i.Method, i.Host, i.Path)
}

/*
UpdateLogTags updates Apex log.Fields map with values from the parameter

	@param tags log.Fields - log.Fields to update
*/
func (i *AccessAuthorizeParam) UpdateLogTags(tags log.Fields) {
	tags["auth_user_id"] = i.UserID
	tags["auth_method"] = i.Method
	tags["auth_path"] = fmt.Sprintf("'%s'", i.Path)
	tags["auth_host"] = i.Host
}

/*
ModifyLogMetadataByAccessAuthorizeParam update log metadata with info from AccessAuthorizeParam

	@param ctxt context.Context - a request context
	@param theTags log.Fields - a log metadata to update
*/
func ModifyLogMetadataByAccessAuthorizeParam(ctxt context.Context, theTags log.Fields) {
	if ctxt.Value(AccessAuthorizeParamKey{}) != nil {
		v, ok := ctxt.Value(AccessAuthorizeParamKey{}).(AccessAuthorizeParam)
		if ok {
			v.UpdateLogTags(theTags)
		}
	}
}
