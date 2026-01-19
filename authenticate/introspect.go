// Package authenticate - user authentication
package authenticate

import (
	"context"
	"time"

	"github.com/alwitt/goutils"
	"github.com/alwitt/padlock/common"
	"github.com/apex/log"
)

// IntrospectFunc signature for a function to call to introspect
type IntrospectFunc func(context.Context, string) (bool, error)

// Introspector perform introspection on given token
type Introspector interface {
	/*
		VerifyToken verify a given token

		@param ctxt context.Context - the operating context
		@param token string - the original token
		@param expire int64 - when the token expires
		@param timestamp time.Time - the current timestamp
		@return whether token is valid
	*/
	VerifyToken(ctxt context.Context, token string, expire int64, timestamp time.Time) (bool, error)
}

// introspectorImpl implements Introspector
type introspectorImpl struct {
	goutils.Component
	cache      TokenCache
	introspect IntrospectFunc
}

/*
DefineIntrospector defines a new introspector object

	@param cache TokenCache - token cache
	@param introspectCB IntrospectFunc - callback function to use to perform introspection
	@return new introspector
*/
func DefineIntrospector(cache TokenCache, introspectCB IntrospectFunc) Introspector {
	logTags := log.Fields{"module": "authenticate", "component": "introspector"}
	return &introspectorImpl{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
				common.ModifyLogMetadataByAccessAuthorizeParam,
			},
		},
		cache:      cache,
		introspect: introspectCB,
	}
}

/*
VerifyToken verify a given token

	@param ctxt context.Context - the operating context
	@param token string - the original token
	@param expire int64 - when the token expires
	@param timestamp time.Time - the current timestamp
	@return whether token is valid
*/
func (i *introspectorImpl) VerifyToken(
	ctxt context.Context, token string, expire int64, timestamp time.Time,
) (bool, error) {
	logtags := i.GetLogTagsForContext(ctxt)

	// Check whether this token was seen before
	isValid, err := i.cache.ValidTokenInCache(ctxt, token, timestamp)
	if err != nil {
		log.WithError(err).WithFields(logtags).Error("Unable to check token cache")
		return false, err
	}
	// Is cached token still valid
	if isValid {
		log.WithFields(logtags).Debugf("Skipping introspection")
		return true, nil
	}

	// Perform introspection
	isValid, err = i.introspect(ctxt, token)
	if err != nil {
		log.WithError(err).WithFields(logtags).Error("Introspection process failed")
		return false, err
	}

	// Token failed introspection
	if !isValid {
		return false, nil
	}

	// Cache the valid token
	if err = i.cache.RecordToken(ctxt, token, expire, timestamp); err != nil {
		log.WithError(err).WithFields(logtags).Error("Unable to write to token cache")
		return true, err
	}
	return true, nil
}
