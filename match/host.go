package match

import (
	"context"
	"fmt"
	"sort"

	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/user"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
)

// ======================================================================================

// targetHostMatcher implements RequestMatch for host level matching
type targetHostMatcher struct {
	common.Component
	targetHost  string
	uriMatchers []*targetURIMatcher
	validate    *validator.Validate
}

/*
defineTargetHostMatcher defines a new RequestMatch for matching request at host level

 @param spec TargetHostSpec - the matcher specification
 @return new targetHostMatcher instance
*/
func defineTargetHostMatcher(spec TargetHostSpec) (*targetHostMatcher, error) {
	validate := validator.New()
	if err := validate.Struct(&spec); err != nil {
		return nil, err
	}
	logTags := log.Fields{
		"module": "match", "component": "host-matcher", "target_host": spec.TargetHost,
	}
	// Build out the URI matchers
	uriMatchers := make([]*targetURIMatcher, 0)
	for _, uriMatchSpec := range spec.AllowedURIsForHost {
		matcher, err := defineTargetURIMatcher(spec.TargetHost, uriMatchSpec)
		if err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Unable to build URI matcher for %s", uriMatchSpec.Pattern)
			return nil, err
		}
		uriMatchers = append(uriMatchers, matcher)
	}
	// Sort the URI matcher by length of pattern
	sort.Slice(uriMatchers, func(i, j int) bool {
		return len(uriMatchers[i].Pattern) > len(uriMatchers[j].Pattern)
	})
	return &targetHostMatcher{
		Component:   common.Component{LogTags: logTags},
		targetHost:  spec.TargetHost,
		uriMatchers: uriMatchers,
		validate:    validate,
	}, nil
}

/*
Match checks whether a request matches against defined parameters

 @param ctxt context.Context - contexting calling this API
 @param request RequestParam - request parameters
 @return if a match, the list permissions needed to proceed
         an error otherwise
*/
func (m *targetHostMatcher) Match(ctxt context.Context, request RequestParam) (
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
	// Find a matching URI
	for _, uriMatcher := range m.uriMatchers {
		uriOK, err := uriMatcher.checkURI(request.URI)
		if err != nil {
			log.WithError(err).
				WithFields(logTags).
				WithField("check_request", request.String()).
				Error("Failed to execute URI REGEX check")
			return nil, err
		}
		// Run the URI matcher
		if uriOK {
			log.WithFields(logTags).WithField("check_request", request.String()).
				Debugf("Matches %s", uriMatcher.Pattern)
			permissions, err := uriMatcher.match(ctxt, request, true)
			if err != nil {
				log.WithError(err).
					WithFields(logTags).
					WithField("check_request", request.String()).
					Error("Failed to execute URI match")
				return nil, err
			}
			if permissions != nil {
				return permissions, nil
			}
			// Keep checking
		}
	}
	return nil, nil
}

/*
String returns an ASCII description of the object

 @return an ASCII description of the object
*/
func (m *targetHostMatcher) String() string {
	return fmt.Sprintf("HOST-MATCH['%s']", m.targetHost)
}
