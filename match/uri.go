package match

import (
	"context"
	"fmt"

	"github.com/alwitt/padlock/common"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
)

// targetPathMatcher implements RequestMatch for path level matching
type targetPathMatcher struct {
	common.Component
	TargetPathSpec
	regex    common.RegexCheck
	validate *validator.Validate
}

/*
defineTargetPathMatcher defines a new RequestMatch for matching request at path level

 @param targetHost string - the host name this matcher is associated with
 @param spec TargetPathSpec - the matcher specification
 @return new targetPathMatcher instance
*/
func defineTargetPathMatcher(targetHost string, spec TargetPathSpec) (*targetPathMatcher, error) {
	validate := validator.New()
	if err := validate.Struct(&spec); err != nil {
		return nil, err
	}
	regex, err := common.NewRegexCheck(spec.PathPattern)
	if err != nil {
		return nil, err
	}
	logTags := log.Fields{
		"module":              "match",
		"component":           "path-matcher",
		"target_host":         targetHost,
		"target_path_pattern": spec.PathPattern,
	}

	// Verify that the methods listed in the PermissionsForMethod are permitted
	type methodCheck struct {
		Methods []string `validate:"required,dive,oneof=GET HEAD PUT POST PATCH DELETE OPTIONS *"`
	}
	{
		check := methodCheck{Methods: make([]string, 0)}
		for method := range spec.PermissionsForMethod {
			check.Methods = append(check.Methods, method)
		}
		if err := validate.Struct(&check); err != nil {
			return nil, err
		}
	}

	return &targetPathMatcher{
		Component:      common.Component{LogTags: logTags},
		TargetPathSpec: spec,
		regex:          regex,
		validate:       validate,
	}, nil
}

// checkPath helper function to check whether the request path matches this instance
func (m *targetPathMatcher) checkPath(requestPath string) (bool, error) {
	return m.regex.Match([]byte(requestPath))
}

/*
match is core logic for targetPathMatcher.Match

 @param ctxt context.Context - context calling this API
 @param request RequestParam - request parameters
 @param skipPathCheck bool - whether to skip the path REGEX matching
 @return if a match, the list permissions needed to proceed
         an error otherwise
*/
func (m *targetPathMatcher) match(ctxt context.Context, request RequestParam, skipPathCheck bool) (
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
	// Verify path matches
	if !skipPathCheck {
		pathMatch, err := m.checkPath(request.Path)
		if err != nil {
			log.WithError(err).
				WithFields(logTags).
				WithField("check_request", request.String()).
				Error("Failed to execute REGEX check")
			return nil, err
		}
		if !pathMatch {
			log.WithFields(logTags).
				WithField("check_request", request.String()).
				WithField("miss", "path").
				Debug("MISMATCH PATH")
			return nil, nil
		}
	}
	// Verify method is known
	permissionsForMethod, ok := m.PermissionsForMethod[request.Method]
	if !ok {
		// Check whether wildcard entry was provided
		permissionsForMethod, ok = m.PermissionsForMethod["*"]
		if !ok {
			log.WithFields(logTags).
				WithField("check_request", request.String()).
				WithField("miss", "method").
				Debug("MISMATCH")
			return nil, nil
		}
	}
	log.WithFields(logTags).WithField("check_request", request.String()).Debug("MATCH")
	return permissionsForMethod, nil
}

/*
Match checks whether a request matches against defined parameters

 @param ctxt context.Context - context calling this API
 @param request RequestParam - request parameters
 @return if a match, the list permissions needed to proceed
         an error otherwise
*/
func (m *targetPathMatcher) Match(ctxt context.Context, request RequestParam) ([]string, error) {
	return m.match(ctxt, request, false)
}

/*
String returns an ASCII description of the object

 @return an ASCII description of the object
*/
func (m *targetPathMatcher) String() string {
	return fmt.Sprintf("PATH-MATCH['%s']", m.PathPattern)
}
