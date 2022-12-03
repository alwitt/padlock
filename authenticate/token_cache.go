package authenticate

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/alwitt/goutils"
	"github.com/alwitt/padlock/common"
	"github.com/apex/log"
	"golang.org/x/net/context"
)

// cacheEntry JWT token entry
type cacheEntry struct {
	// When the token expires
	expire int64
	// When the token was cached
	recorded time.Time
}

// TokenCache cache for recording and fetching tokens encountered
type TokenCache interface {
	/*
		RecordToken cache a new token

		@param ctxt context.Context - the operating context
		@param token string - the original token
		@param expire int64 - when the token expires
		@param timestamp time.Time - the current timestamp
		@return whether caching was successful
	*/
	RecordToken(ctxt context.Context, token string, expire int64, timestamp time.Time) error

	/*
		RecordToken remote a token from cache

		@param ctxt context.Context - the operating context
		@param token string - the original token
		@return whether delete was successful
	*/
	RemoveToken(ctxt context.Context, token string) error

	/*
		ValidTokenInCache check whether this token is already cached and valid.

		If the token is present, but requires re-validation, this function will remove the
		token from cache and indicate no valid token is cached.

		@param ctxt context.Context - the operating context
		@param token string - the original token
		@param timestamp time.Time - the current timestamp
		@return whether it is present and valid
	*/
	ValidTokenInCache(ctxt context.Context, token string, timestamp time.Time) (bool, error)

	/*
		RemoveExpiredFromCache remove all expired tokens from cache

		@param ctxt context.Context - the operating context
		@param timestamp time.Time - the current timestamp
		@return whether successful
	*/
	RemoveExpiredFromCache(ctxt context.Context, timestamp time.Time) error
}

// tokenCacheImpl implements TokenCache
type tokenCacheImpl struct {
	goutils.Component
	lock       sync.RWMutex
	cache      map[string]cacheEntry
	refreshInt time.Duration
}

/*
DefineTokenCache defines a new token cache object

	@param refreshInt time.Duration - a token must to be re-validated after this duration
	@return new cache instance
*/
func DefineTokenCache(refreshInt time.Duration) TokenCache {
	logTags := log.Fields{"module": "authenticate", "component": "token-cache"}
	return &tokenCacheImpl{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
				common.ModifyLogMetadataByAccessAuthorizeParam,
			},
		},
		lock:       sync.RWMutex{},
		cache:      make(map[string]cacheEntry),
		refreshInt: refreshInt,
	}
}

// getTokenHash compute SHA1 sum of a token
func getTokenHash(token string) (string, error) {
	hasher := sha1.New()
	written, err := hasher.Write([]byte(token))
	if err != nil {
		return "", err
	}
	if written != len(token) {
		return "", fmt.Errorf("failed to hash token")
	}
	return base64.URLEncoding.EncodeToString(hasher.Sum(nil)), nil
}

// packageToken wrap a new token in TokenEntry envelope
func packageToken(token string, expire int64, timestamp time.Time) (string, cacheEntry, error) {
	tokenHashSum, err := getTokenHash(token)
	if err != nil {
		return "", cacheEntry{}, err
	}
	return tokenHashSum, cacheEntry{expire: expire, recorded: timestamp}, nil
}

/*
RecordToken cache a new token

	@param ctxt context.Context - the operating context
	@param token string - the original token
	@param expire int64 - when the token expires
	@return whether caching was successful
*/
func (c *tokenCacheImpl) RecordToken(
	ctxt context.Context, token string, expire int64, timestamp time.Time,
) error {
	logtags := c.GetLogTagsForContext(ctxt)

	// Compute the token hash
	tokenHash, entry, err := packageToken(token, expire, timestamp)
	if err != nil {
		log.WithError(err).WithFields(logtags).Error("Failed to compute token hash for recording")
		return err
	}

	// Record the token
	{
		c.lock.Lock()
		c.cache[tokenHash] = entry
		c.lock.Unlock()
	}
	log.WithFields(logtags).Debugf("Adding token [%s] to cache", tokenHash)
	return nil
}

/*
RecordToken remote a token from cache

	@param ctxt context.Context - the operating context
	@param token string - the original token
	@return whether delete was successful
*/
func (c *tokenCacheImpl) RemoveToken(ctxt context.Context, token string) error {
	logtags := c.GetLogTagsForContext(ctxt)

	// Compute the token hash
	tokenHash, err := getTokenHash(token)
	if err != nil {
		log.WithError(err).WithFields(logtags).Error("Failed to compute token hash for deletion")
		return err
	}

	// Remove the token
	{
		c.lock.Lock()
		delete(c.cache, tokenHash)
		c.lock.Unlock()
	}
	log.WithFields(logtags).Debugf("Deleting token [%s] from cache", tokenHash)
	return nil
}

/*
ValidTokenInCache check whether this token is already cached and valid

If the token is present, but requires re-validation, this function will remove the
token from cache and indicate no valid token is cached.

	@param ctxt context.Context - the operating context
	@param token string - the original token
	@param timestamp time.Time - the current timestamp
	@return whether it is present and valid
*/
func (c *tokenCacheImpl) ValidTokenInCache(
	ctxt context.Context, token string, timestamp time.Time,
) (bool, error) {
	logtags := c.GetLogTagsForContext(ctxt)

	// Compute the token hash
	tokenHash, err := getTokenHash(token)
	if err != nil {
		log.WithError(err).WithFields(logtags).Error("Failed to compute token hash for verification")
		return false, err
	}

	// Check whether the token exist
	var existingEntry cacheEntry
	{
		c.lock.RLocker().Lock()
		entry, ok := c.cache[tokenHash]
		if !ok {
			log.WithFields(logtags).Infof("Token [%s] is unknown", tokenHash)
			c.lock.RLocker().Unlock()
			return false, nil
		}
		existingEntry = entry
		c.lock.RLocker().Unlock()
	}

	removeToken := func() {
		c.lock.Lock()
		delete(c.cache, tokenHash)
		c.lock.Unlock()
	}

	log.WithFields(logtags).Debugf(
		"Token [%s], recorded at %d, expire at %d. Current time %d",
		tokenHash,
		existingEntry.recorded.Unix(),
		existingEntry.expire,
		timestamp.Unix(),
	)

	// Check whether the token has expired
	if timestamp.Unix() > existingEntry.expire {
		log.WithFields(logtags).Infof("Token [%s] has expired. Removing from cache...", tokenHash)
		removeToken()
		return false, nil
	}

	// Check whether the cache entry need to be refreshed
	if timestamp.After(existingEntry.recorded) && timestamp.Sub(existingEntry.recorded) > c.refreshInt {
		log.WithFields(logtags).Infof(
			"Token [%s] needs to be re-validated. Removing from cache...", tokenHash,
		)
		removeToken()
		return false, nil
	}

	log.WithFields(logtags).Debugf("Token [%s] still valid", tokenHash)
	return true, nil
}

/*
RemoveExpiredFromCache remove all expired tokens from cache

	@param ctxt context.Context - the operating context
	@param timestamp time.Time - the current timestamp
	@return whether successful
*/
func (c *tokenCacheImpl) RemoveExpiredFromCache(ctxt context.Context, timestamp time.Time) error {
	logtags := c.GetLogTagsForContext(ctxt)
	c.lock.Lock()
	defer c.lock.Unlock()
	toRemove := []string{}
	for id, entry := range c.cache {
		if timestamp.Unix() >= entry.expire {
			toRemove = append(toRemove, id)
		}
	}
	for _, id := range toRemove {
		delete(c.cache, id)
		log.WithFields(logtags).Infof("Token [%s] has expired. Removing from cache...", id)
	}
	return nil
}
