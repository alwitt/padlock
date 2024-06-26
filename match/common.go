package match

import (
	"context"
	"fmt"
	"net/url"

	"github.com/alwitt/padlock/common"
	"github.com/go-playground/validator/v10"
)

// RequestParam contains critical parameters describing a REST request
type RequestParam struct {
	// Host is the request target "host"
	Host *string `validate:"omitempty,fqdn"`
	// Path is the request target Path
	Path string `validate:"required,uri"`
	// Method is the request method
	Method string `validate:"required,oneof=GET HEAD PUT POST PATCH DELETE OPTIONS"`
}

/*
String returns an ASCII description of the object

	@return an ASCII description of the object
*/
func (p RequestParam) String() string {
	if p.Host != nil {
		return fmt.Sprintf("'%s %s %s'", p.Method, *p.Host, p.Path)
	}
	return fmt.Sprintf("'%s %s'", p.Method, p.Path)
}

// validate perform the validation
func (p RequestParam) validate(validate *validator.Validate) error {
	return validate.Struct(&p)
}

// TargetPathSpec is a single path pattern to check against
type TargetPathSpec struct {
	// PathPattern is the pattern for matching against a request URI path
	PathPattern string `validate:"required"`
	// PermissionsForMethod is the DICT of required permission for each specified request
	// method that is allowed for this path. The method key of "*" functions as a wildcard.
	// If the request method is not explicitly listed here, it may match against "*" if that
	// key was defined.
	PermissionsForMethod map[string][]string `validate:"required,min=1"`
}

// TargetHostSpec is a single host to check against defined by multiple associated paths
type TargetHostSpec struct {
	// TargetHost is the host value the URI are associated with
	TargetHost string `validate:"required"`
	// AllowedPathsForHost is the list of paths associated with this host
	AllowedPathsForHost []TargetPathSpec `validate:"required,min=1,dive"`
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
		 @return if a match, the list permissions needed to proceed, or an error otherwise
	*/
	Match(ctxt context.Context, request RequestParam) ([]string, error)

	/*
		String returns an ASCII description of the object

		 @return an ASCII description of the object
	*/
	String() string
}

/*
ConvertConfigToTargetGroupSpec convert a common.AuthorizationConfig into TargetGroupSpec

	@param cfg *common.AuthorizationConfig -  the authorize config section
	@return the converted TargetGroupSpec
*/
func ConvertConfigToTargetGroupSpec(cfg *common.AuthorizationConfig) (TargetGroupSpec, error) {
	result := TargetGroupSpec{AllowedHosts: make(map[string]TargetHostSpec)}

	// Go through eaach target hosts
	for _, oneTargetHost := range cfg.Rules {
		hostSpec := TargetHostSpec{
			TargetHost: oneTargetHost.Host, AllowedPathsForHost: make([]TargetPathSpec, 0),
		}
		for _, oneTargetPath := range oneTargetHost.TargetPaths {
			pathSpec := TargetPathSpec{
				PathPattern:          oneTargetPath.PathRegexPattern,
				PermissionsForMethod: make(map[string][]string),
			}
			for _, oneTargetMethod := range oneTargetPath.AllowedMethods {
				pathSpec.PermissionsForMethod[oneTargetMethod.Method] = oneTargetMethod.Permissions
			}
			hostSpec.AllowedPathsForHost = append(hostSpec.AllowedPathsForHost, pathSpec)
		}
		result.AllowedHosts[oneTargetHost.Host] = hostSpec
	}

	return result, nil
}

/*
GetAbsPath given a URI path, normalize it and remove any relative references

	@param original string - Original URI path
	@return the absolute path
*/
func GetAbsPath(original string) (string, error) {
	parsedOriginal, err := url.Parse(original)
	if err != nil {
		return "", err
	}

	baseURL, _ := url.Parse("/")
	absPath := baseURL.ResolveReference(parsedOriginal)

	return absPath.String(), nil
}
