package match

import (
	"context"
	"fmt"
	"sort"

	"github.com/alwitt/goutils"
	"github.com/alwitt/padlock/common"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
)

// ======================================================================================

// targetHostMatcher implements RequestMatch for host level matching
type targetHostMatcher struct {
	goutils.Component
	targetHost   string
	pathMatchers []*targetPathMatcher
	validate     *validator.Validate
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
	// Build out the path matchers
	pathMatchers := make([]*targetPathMatcher, 0)
	for _, pathMatchSpec := range spec.AllowedPathsForHost {
		matcher, err := defineTargetPathMatcher(spec.TargetHost, pathMatchSpec)
		if err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Unable to build path matcher for %s", pathMatchSpec.PathPattern)
			return nil, err
		}
		pathMatchers = append(pathMatchers, matcher)
	}
	// Sort the path matcher by length of pattern
	sort.Slice(pathMatchers, func(i, j int) bool {
		return len(pathMatchers[i].PathPattern) > len(pathMatchers[j].PathPattern)
	})
	return &targetHostMatcher{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
				common.ModifyLogMetadataByAccessAuthorizeParam,
			},
		},
		targetHost:   spec.TargetHost,
		pathMatchers: pathMatchers,
		validate:     validate,
	}, nil
}

/*
Match checks whether a request matches against defined parameters

 @param ctxt context.Context - context calling this API
 @param request RequestParam - request parameters
 @return if a match, the list permissions needed to proceed
         an error otherwise
*/
func (m *targetHostMatcher) Match(ctxt context.Context, request RequestParam) (
	[]string, error,
) {
	logTags := m.GetLogTagsForContext(ctxt)
	// Verify the request is considered valid
	if err := request.validate(m.validate); err != nil {
		log.WithError(err).WithFields(logTags).
			WithField("check_request", request.String()).
			Error("Invalid request check parameters")
		return nil, err
	}
	// Find a matching path
	for _, pathMatcher := range m.pathMatchers {
		pathOK, err := pathMatcher.checkPath(request.Path)
		if err != nil {
			log.WithError(err).
				WithFields(logTags).
				WithField("check_request", request.String()).
				Error("Failed to execute path REGEX check")
			return nil, err
		}
		// Run the path matcher
		if pathOK {
			log.WithFields(logTags).WithField("check_request", request.String()).
				Debugf("Matches %s", pathMatcher.PathPattern)
			permissions, err := pathMatcher.match(ctxt, request, true)
			if err != nil {
				log.WithError(err).
					WithFields(logTags).
					WithField("check_request", request.String()).
					Error("Failed to execute path match")
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
