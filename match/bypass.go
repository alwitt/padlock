// Package match - authorization rule match package
package match

import (
	"context"
	"strings"

	"github.com/alwitt/goutils"
	"github.com/alwitt/padlock/common"
	"github.com/apex/log"
)

// bypassMethodMatcher determine whether a request can bypass auth because of method match
type bypassMethodMatcher struct {
	goutils.Component
	// matches set of request methods which are allowed for auth bypass
	matches map[string]bool
}

/*
Match checks whether a request matches against auth bypass rules

	@param ctxt context.Context - context calling this API
	@param request RequestParam - request parameters
	@return if a match is found or not, or an error otherwise
*/
func (m *bypassMethodMatcher) Match(ctxt context.Context, request RequestParam) (bool, error) {
	logTags := m.GetLogTagsForContext(ctxt)
	if _, ok := m.matches[strings.ToLower(request.Method)]; ok {
		log.
			WithFields(logTags).
			Debug("Request allowed to bypass auth as method matches")
		return true, nil
	}
	return false, nil
}

/*
defineBypassMethodMatcher defines a new AuthBypassMatch for matching request methods

	@param matches []string - the request methods to allow bypass
	@return new bypassMethodMatcher instance
*/
func defineBypassMethodMatcher(matches []string) (AuthBypassMatch, error) {
	logTags := log.Fields{
		"module":    "match",
		"component": "bypass-method-matcher",
	}

	instance := &bypassMethodMatcher{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
				common.ModifyLogMetadataByAccessAuthorizeParam,
			},
		},
		matches: make(map[string]bool),
	}
	for _, oneMatch := range matches {
		instance.matches[strings.ToLower(oneMatch)] = true
	}

	return instance, nil
}

// bypassHostMatcher determine whether a request can bypass auth because of host match
type bypassHostMatcher struct {
	goutils.Component
	// matches set of hosts which are allowed for auth bypass
	matches map[string]bool
}

/*
Match checks whether a request matches against auth bypass rules

	@param ctxt context.Context - context calling this API
	@param request RequestParam - request parameters
	@return if a match is found or not, or an error otherwise
*/
func (m *bypassHostMatcher) Match(ctxt context.Context, request RequestParam) (bool, error) {
	logTags := m.GetLogTagsForContext(ctxt)
	if request.Host == nil {
		return false, nil
	}
	if _, ok := m.matches[strings.ToLower(*request.Host)]; ok {
		log.
			WithFields(logTags).
			Debug("Request allowed to bypass auth as host matches")
		return true, nil
	}
	return false, nil
}

/*
defineBypassHostMatcher defines a new AuthBypassMatch for matching request hosts

	@param matches []string - the request hosts to allow bypass
	@return new bypassHostMatcher instance
*/
func defineBypassHostMatcher(matches []string) (AuthBypassMatch, error) {
	logTags := log.Fields{
		"module":    "match",
		"component": "bypass-host-matcher",
	}

	instance := &bypassHostMatcher{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
				common.ModifyLogMetadataByAccessAuthorizeParam,
			},
		},
		matches: make(map[string]bool),
	}
	for _, oneMatch := range matches {
		instance.matches[strings.ToLower(oneMatch)] = true
	}

	return instance, nil
}

// bypassPathMatcher determine whether a request can bypass auth because of URI path match
type bypassPathMatcher struct {
	goutils.Component
	// matches set of URI paths which are allowed for auth bypass
	matches map[string]common.RegexCheck
}

/*
Match checks whether a request matches against auth bypass rules

	@param ctxt context.Context - context calling this API
	@param request RequestParam - request parameters
	@return if a match is found or not, or an error otherwise
*/
func (m *bypassPathMatcher) Match(ctxt context.Context, request RequestParam) (bool, error) {
	logTags := m.GetLogTagsForContext(ctxt)
	for regPattern, oneMatch := range m.matches {
		if matched, err := oneMatch.Match([]byte(request.Path)); err != nil {
			continue
		} else if matched {
			log.
				WithFields(logTags).
				WithField("regex-pattern", regPattern).
				Debug("Request allowed to bypass auth as URI path matches")
			return true, nil
		}
	}
	return false, nil
}

/*
defineBypassPathMatcher defines a new AuthBypassMatch for matching request URI path

	@param matches []string - the request path to allow bypass
	@return new bypassHostMatcher instance
*/
func defineBypassPathMatcher(matches []string) (AuthBypassMatch, error) {
	logTags := log.Fields{
		"module":    "match",
		"component": "bypass-uri-path-matcher",
	}

	instance := &bypassPathMatcher{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
				common.ModifyLogMetadataByAccessAuthorizeParam,
			},
		},
		matches: make(map[string]common.RegexCheck),
	}
	for _, oneMatch := range matches {
		matcher, err := common.NewRegexCheck(oneMatch)
		if err != nil {
			log.
				WithError(err).
				WithFields(logTags).
				WithField("regex-pattern", oneMatch).
				Error("Failed to define REGEX checker")
			return nil, err
		}
		instance.matches[oneMatch] = matcher
	}

	return instance, nil
}

// AuthBypassMatch check whether a request matches against auth bypass rules
type AuthBypassMatch interface {
	/*
		Match checks whether a request matches against auth bypass rules

			@param ctxt context.Context - context calling this API
			@param request RequestParam - request parameters
			@return if a match is found or not, or an error otherwise
	*/
	Match(ctxt context.Context, request RequestParam) (bool, error)
}

// authBypassMatchImpl implements AuthBypassMatch
type authBypassMatchImpl struct {
	goutils.Component
	matchers map[string]AuthBypassMatch
}

/*
DefineAuthBypassMatch defines a new AuthBypassMatch

	@param config common.AuthnBypassConfig - matcher configuration
	@return new AuthBypassMatch instance
*/
func DefineAuthBypassMatch(config common.AuthnBypassConfig) (AuthBypassMatch, error) {
	/*
		System currently supports match on
		* method
		* host
		* path
	*/

	matchConfigs := map[string][]string{
		"method": {}, "host": {}, "path": {},
	}

	for _, oneConfig := range config.Rules {
		matchConfigs[oneConfig.MatchType] = append(
			matchConfigs[oneConfig.MatchType], oneConfig.Matches...,
		)
	}

	// Define the matchers
	logTags := log.Fields{
		"module":    "match",
		"component": "auth-bypass-matcher",
	}
	instance := &authBypassMatchImpl{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
				common.ModifyLogMetadataByAccessAuthorizeParam,
			},
		},
		matchers: map[string]AuthBypassMatch{},
	}
	if conditions := matchConfigs["method"]; len(conditions) > 0 {
		matcher, err := defineBypassMethodMatcher(conditions)
		if err != nil {
			log.
				WithError(err).
				WithFields(logTags).
				Error("Failed to define 'for method' auth bypass matcher")
			return nil, err
		}
		instance.matchers["method"] = matcher
	}
	if conditions := matchConfigs["host"]; len(conditions) > 0 {
		matcher, err := defineBypassHostMatcher(conditions)
		if err != nil {
			log.
				WithError(err).
				WithFields(logTags).
				Error("Failed to define 'for host' auth bypass matcher")
			return nil, err
		}
		instance.matchers["host"] = matcher
	}
	if conditions := matchConfigs["path"]; len(conditions) > 0 {
		matcher, err := defineBypassPathMatcher(conditions)
		if err != nil {
			log.
				WithError(err).
				WithFields(logTags).
				Error("Failed to define 'for path' auth bypass matcher")
			return nil, err
		}
		instance.matchers["path"] = matcher
	}

	return instance, nil
}

/*
Match checks whether a request matches against auth bypass rules

	@param ctxt context.Context - context calling this API
	@param request RequestParam - request parameters
	@return if a match is found or not, or an error otherwise
*/
func (m *authBypassMatchImpl) Match(ctxt context.Context, request RequestParam) (bool, error) {
	logTags := m.GetLogTagsForContext(ctxt)

	// Go through each available matcher
	for matcherType, matcher := range m.matchers {
		matched, err := matcher.Match(ctxt, request)
		if err != nil {
			log.
				WithError(err).
				WithFields(logTags).
				WithField("matcher-type", matcherType).
				Error("Matcher failed to process request")
			continue
		}
		if matched {
			return true, nil
		}
	}

	return false, nil
}
