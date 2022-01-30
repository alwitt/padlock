package match

import (
	"context"

	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/user"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
)

// ======================================================================================

// targetGroupMatcher implements RequestMatch for host group level matching
type targetGroupMatcher struct {
	common.Component
	hostMatchers map[string]*targetHostMatcher
	validate     *validator.Validate
}

/*
DefineTargetGroupMatcher defines a new RequestMatch for matching at host group level

 @param spec TargetGroupSpec - the matcher specification
 @return new RequestMatch instance
*/
func DefineTargetGroupMatcher(spec TargetGroupSpec) (RequestMatch, error) {
	validate := validator.New()
	if err := validate.Struct(&spec); err != nil {
		return nil, err
	}
	logTags := log.Fields{"module": "match", "component": "group-matcher"}
	// Build out the Host matchers
	hostMatchers := map[string]*targetHostMatcher{}
	for hostName, matcherSpec := range spec.AllowedHosts {
		matcher, err := defineTargetHostMatcher(matcherSpec)
		if err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Unable to build Hhost matcher for %s", hostName)
			return nil, err
		}
		hostMatchers[hostName] = matcher
	}
	return &targetGroupMatcher{
		Component: common.Component{LogTags: logTags}, hostMatchers: hostMatchers, validate: validate,
	}, nil
}

/*
Match checks whether a request matches against defined parameters

 @param ctxt context.Context - contexting calling this API
 @param request RequestParam - request parameters
 @return if a match, the list permissions needed to proceed
         an error otherwise
*/
func (m *targetGroupMatcher) Match(ctxt context.Context, request RequestParam) (
	[]user.Permission, error,
) {
	logTags := m.GetLogTagsForContext(ctxt)
	// Verify the request is considered valid
	if err := request.validate(m.validate); err != nil {
		log.WithError(err).WithFields(logTags).
			WithField("check_request", request.String()).
			Error("Invalid request check parameters")
		return nil, err
	}
	// Find a matching host, use "*" if not provided
	if request.Host != nil {
		matcher, ok := m.hostMatchers[*request.Host]
		if ok {
			permissions, err := matcher.Match(ctxt, request)
			if err != nil {
				log.WithError(err).
					WithFields(logTags).
					WithField("check_request", request.String()).
					Error("Failed to execute HOST match")
				return nil, err
			}
			if permissions != nil {
				return permissions, nil
			}
		}
	}
	// Check with wildcard instead
	matcher, ok := m.hostMatchers["*"]
	if ok {
		permissions, err := matcher.Match(ctxt, request)
		if err != nil {
			log.WithError(err).
				WithFields(logTags).
				WithField("check_request", request.String()).
				Error("Failed to execute HOST match")
			return nil, err
		}
		if permissions != nil {
			return permissions, nil
		}
	}
	return nil, nil
}

/*
String returns an ASCII description of the object

 @return an ASCII description of the object
*/
func (m *targetGroupMatcher) String() string {
	return "HOST-GROUP-MATCH"
}
