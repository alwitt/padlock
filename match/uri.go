package match

import (
	"context"
	"fmt"

	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/user"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
)

// targetURIMatcher implements RequestMatch
type targetURIMatcher struct {
	common.Component
	TargetURISpec
	regex    RegexCheck
	validate *validator.Validate
}

/*
defineTargetURIMatcher defines a new RequestMatch for matching request at URI level
*/
func defineTargetURIMatcher(spec TargetURISpec) (*targetURIMatcher, error) {
	validate := validator.New()
	if err := validate.Struct(&spec); err != nil {
		return nil, err
	}
	regex, err := NewRegexCheck(spec.Pattern)
	if err != nil {
		return nil, err
	}
	logTags := log.Fields{
		"module": "match", "component": "uri-matcher", "instance": spec.Pattern,
	}
	return &targetURIMatcher{
		Component:     common.Component{LogTags: logTags},
		TargetURISpec: spec,
		regex:         regex,
		validate:      validate,
	}, nil
}

// checkURI helper function to check whether the request URI matches this instance
func (m *targetURIMatcher) checkURI(requestURI string) (bool, error) {
	return m.regex.Match([]byte(requestURI))
}

// match is core logic for targetURIMatcher.Match
/*
match is core logic for targetURIMatcher.Match

 @param ctxt context.Context - contexting calling this API
 @param request RequestParam - request parameters
 @param skipURICheck bool - whether to skip the URI REGEX matching
 @return if a match, the list permissions needed to proceed
         an error otherwise
*/
func (m *targetURIMatcher) match(ctxt context.Context, request RequestParam, skipURICheck bool) (
	[]user.Permission, error,
) {
	logTags := m.GetLogTagsForContext(ctxt)
	// Verify the request is still considered valid
	if err := request.validate(m.validate); err != nil {
		log.WithError(err).WithFields(logTags).
			WithField("check_request", request.String()).
			Error("Invalid request check parameters")
		return nil, err
	}
	// Verify URI matches
	if !skipURICheck {
		uriMatch, err := m.checkURI(request.URI)
		if err != nil {
			log.WithError(err).
				WithFields(logTags).
				WithField("check_request", request.String()).
				Error("Failed to execute REGEX check")
			return nil, err
		}
		if !uriMatch {
			log.WithFields(logTags).
				WithField("check_request", request.String()).
				WithField("miss", "URI").
				Debug("MISMATCH URI")
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

 @param ctxt context.Context - contexting calling this API
 @param request RequestParam - request parameters
 @return if a match, the list permissions needed to proceed
         an error otherwise
*/
func (m *targetURIMatcher) Match(ctxt context.Context, request RequestParam) (
	[]user.Permission, error,
) {
	return m.match(ctxt, request, false)
}

/*
String returns an ASCII description of the object

 @return an ASCII description of the object
*/
func (m *targetURIMatcher) String() string {
	return fmt.Sprintf("URI-MATCH['%s']", m.Pattern)
}