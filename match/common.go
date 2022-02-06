package match

import (
	"context"
	"fmt"

	"github.com/go-playground/validator/v10"
)

// RequestParam contains critical parameters describing a REST request
type RequestParam struct {
	// Host is the request target "host"
	Host *string `validate:"omitempty,fqdn"`
	// URI is the request target URI portion after the Authority
	URI string `validate:"required,uri"`
	// Method is the request method
	Method string `validate:"required,oneof=GET HEAD PUT POST PATCH DELETE OPTIONS"`
}

/*
String returns an ASCII description of the object

 @return an ASCII description of the object
*/
func (p RequestParam) String() string {
	if p.Host != nil {
		return fmt.Sprintf("'%s %s %s'", p.Method, *p.Host, p.URI)
	}
	return fmt.Sprintf("'%s %s'", p.Method, p.URI)
}

// validate perform the validation
func (p RequestParam) validate(validate *validator.Validate) error {
	return validate.Struct(&p)
}

// TargetURISpec is a single URI pattern to check against
type TargetURISpec struct {
	// Pattern is the pattern for matching against a request URI (portion after the Authority)
	Pattern string `validate:"required"`
	// PermissionsForMethod is the DICT of required permission for each specified request
	// method that is allowed for this URI. The method key of "*" functions as a wildcard.
	// If the request method is not explicitly listed here, it may match against "*" if that
	// key was defined.
	PermissionsForMethod map[string][]string `validate:"required,min=1"`
}

// TargetHostSpec is a single host to check against defined by multiple associated URIs
type TargetHostSpec struct {
	// TargetHost is the host value the URI are associated with
	TargetHost string `validate:"required"`
	// AllowedURIsForHost is the list of URIs associated with this host
	AllowedURIsForHost []TargetURISpec `validate:"required,min=1,dive"`
}

// TargetGroupSpec is a groups of hosts to check against
type TargetGroupSpec struct {
	// AllowedHosts is the list of TargetHostSpec keyed by the host name. The host key of "*"
	// functions as a wildcard. If a request host is not explicitly listed here, it may match
	// against "*" if that key was defined
	AllowedHosts map[string]TargetHostSpec `validate:"required,min=1,dive"`
}

// RequestMatch checks whether a request matches against defined parameters
type RequestMatch interface {
	/*
		Match checks whether a request matches against defined parameters

		 @param ctxt context.Context - context calling this API
		 @param request RequestParam - request parameters
		 @return if a match, the list permissions needed to proceed
		         an error otherwise
	*/
	Match(ctxt context.Context, request RequestParam) ([]string, error)

	/*
		String returns an ASCII description of the object

		 @return an ASCII description of the object
	*/
	String() string
}
