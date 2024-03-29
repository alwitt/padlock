package common

import (
	"github.com/alwitt/goutils"
	"github.com/spf13/viper"
)

// ===============================================================================
// Utility Config

// CustomValidationsConfig provides the custom validation regex patterns
type CustomValidationsConfig struct {
	// UserIDRegex is the regex pattern used to validate a user ID
	UserIDRegex string `mapstructure:"userID" json:"userID" validate:"required"`
	// UserNameRegex is the regex pattern used to validate a username
	UserNameRegex string `mapstructure:"username" json:"username" validate:"required"`
	// PersonalNameRegex is the regex pattern used to validate a personal name
	PersonalNameRegex string `mapstructure:"personalName" json:"personalName" validate:"required"`
	// RoleNameRegex is the regex pattern used to validate a role name
	RoleNameRegex string `mapstructure:"roleName" json:"roleName" validate:"required"`
	// PermissionRegex is the regex pattern used to validate a permission name
	PermissionRegex string `mapstructure:"permission" json:"permission" validate:"required"`
}

/*
DefineCustomFieldValidator defines a CustomFieldValidator based on the config parameters

	@return the defined CustomFieldValidator
*/
func (c CustomValidationsConfig) DefineCustomFieldValidator() (CustomFieldValidator, error) {
	return GetCustomFieldValidator(
		c.UserIDRegex, c.UserNameRegex, c.PersonalNameRegex, c.RoleNameRegex, c.PermissionRegex,
	)
}

// ===============================================================================
// Common Submodule Config

// HTTPServerTimeoutConfig defines the timeout settings for HTTP server
type HTTPServerTimeoutConfig struct {
	// ReadTimeout is the maximum duration for reading the entire
	// request, including the body in seconds. A zero or negative
	// value means there will be no timeout.
	ReadTimeout int `mapstructure:"read" json:"read" validate:"gte=0"`
	// WriteTimeout is the maximum duration before timing out
	// writes of the response in seconds. A zero or negative value
	// means there will be no timeout.
	WriteTimeout int `mapstructure:"write" json:"write" validate:"gte=0"`
	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled in seconds. If
	// IdleTimeout is zero, the value of ReadTimeout is used. If
	// both are zero, there is no timeout.
	IdleTimeout int `mapstructure:"idle" json:"idle" validate:"gte=0"`
}

// HTTPServerConfig defines the HTTP server parameters
type HTTPServerConfig struct {
	// ListenOn is the interface the HTTP server will listen on
	ListenOn string `mapstructure:"listenOn" json:"listenOn" validate:"required,ip"`
	// Port is the port the HTTP server will listen on
	Port uint16 `mapstructure:"appPort" json:"appPort" validate:"required,gt=0,lt=65536"`
	// Timeouts sets the HTTP timeout settings
	Timeouts HTTPServerTimeoutConfig `mapstructure:"timeoutSecs" json:"timeoutSecs" validate:"required,dive"`
}

// HTTPRequestLogging defines HTTP request logging parameters
type HTTPRequestLogging struct {
	// LogLevel output request logs at this level
	LogLevel goutils.HTTPRequestLogLevel `mapstructure:"logLevel" json:"logLevel" validate:"oneof=warn info debug"`
	// HealthLogLevel output health check logs at this level
	HealthLogLevel goutils.HTTPRequestLogLevel `mapstructure:"healthLogLevel" json:"healthLogLevel" validate:"oneof=warn info debug"`
	// RequestIDHeader is the HTTP header containing the API request ID
	RequestIDHeader string `mapstructure:"requestIDHeader" json:"requestIDHeader"`
	// DoNotLogHeaders is the list of headers to not include in logging metadata
	DoNotLogHeaders []string `mapstructure:"skipHeaders" json:"skipHeaders"`
}

// EndpointConfig defines API endpoint config
type EndpointConfig struct {
	// PathPrefix is the end-point path prefix for the APIs
	PathPrefix string `mapstructure:"pathPrefix" json:"pathPrefix" validate:"required"`
}

// APIConfig defines API settings for a submodule
type APIConfig struct {
	// Endpoint sets API endpoint related parameters
	Endpoint EndpointConfig `mapstructure:"endPoint" json:"endPoint" validate:"required,dive"`
	// RequestLogging sets API request logging parameters
	RequestLogging HTTPRequestLogging `mapstructure:"requestLogging" json:"requestLogging" validate:"required,dive"`
}

// APIServerConfig defines HTTP API / server parameters
type APIServerConfig struct {
	// Enabled whether this API is enabled
	Enabled bool `mapstructure:"enabled" json:"enabled"`
	// Server defines HTTP server parameters
	Server HTTPServerConfig `mapstructure:"service" json:"service" validate:"required_with=Enabled,dive"`
	// APIs defines API settings for a submodule
	APIs APIConfig `mapstructure:"apis" json:"apis" validate:"required_with=Enabled,dive"`
}

// MetricsFeatureConfig metrics framework features config
type MetricsFeatureConfig struct {
	// EnableAppMetrics whether to enable Golang application metrics
	EnableAppMetrics bool `mapstructure:"enableAppMetrics" json:"enableAppMetrics"`
}

// MetricsConfig application metrics config
type MetricsConfig struct {
	// Server defines HTTP server parameters
	Server HTTPServerConfig `mapstructure:"service" json:"service" validate:"required_with=Enabled,dive"`
	// MetricsEndpoint path to host the Prometheus metrics endpoint
	MetricsEndpoint string `mapstructure:"metricsEndpoint" json:"metricsEndpoint" validate:"required"`
	// MaxRequests max number of metrics requests in parallel to support
	MaxRequests int `mapstructure:"maxRequests" json:"maxRequests" validate:"gte=1"`
	// Features metrics framework features to enable
	Features MetricsFeatureConfig `mapstructure:"features" json:"features" validate:"gte=1"`
}

// ===============================================================================
// Database Config

// DatabaseConfig database related configuration
type DatabaseConfig struct {
	// Host is the DB host
	Host string `json:"host" validate:"required"`
	// DB is the database name
	DB string `json:"db" validate:"required"`
	// User is the database user
	User string `json:"user" validate:"required"`
}

// ===============================================================================
// User Role Config

// UserRoleConfig a single user role
type UserRoleConfig struct {
	// AssignedPermissions is the list of permissions assigned to a role
	AssignedPermissions []string `mapstructure:"permissions" json:"permissions" validate:"required,gte=1,dive,user_permissions"`
}

// UserRolesConfig a group of user roles
type UserRolesConfig struct {
	// AvailableRoles is the set of roles supported by the system
	AvailableRoles map[string]UserRoleConfig `mapstructure:"userRoles" json:"userRoles" validate:"required_with=Enabled,dive"`
}

// ===============================================================================
// User Management Submodule Config

// UserManageSubmodule defines user management submodule config
type UserManageSubmodule struct {
	APIServerConfig `mapstructure:",squash"`
	UserRolesConfig `mapstructure:",squash"`
}

// ===============================================================================
// REST API Authentication Config

// AuthenticateRequestParamLocConfig defines which HTTP headers to parse to get the parameters of
// a REST request to authenticate. It is expected that the component (i.e. a proxy) requesting
// authentication for a request will provide the needed values through these headers when it
// contacts the authentication server.
type AuthenticateRequestParamLocConfig struct {
	// Host is the host / FQDN of the request being authenticated
	Host string `mapstructure:"host" json:"host" validate:"required"`
	// Path is the URI path of the request being authenticated
	Path string `mapstructure:"path" json:"path" validate:"required"`
	// Method is the HTTP method of the request being authenticated
	Method string `mapstructure:"method" json:"method" validate:"required"`
}

// AuthnBypassMatchEntry one authentication bypass rule
type AuthnBypassMatchEntry struct {
	// MatchType indicates which request element this rules applies to
	MatchType string `mapstructure:"type" json:"type" validate:"required,oneof=method host path"`
	// Matches if a request property matches one of the possibilities, the request can
	// bypass authentication.
	Matches []string `mapstructure:"matches" json:"matches" validate:"required,gte=1"`
}

// AuthnBypassConfig authentication bypass configuration
type AuthnBypassConfig struct {
	// Rules the authentication bypass rules to check against
	Rules []AuthnBypassMatchEntry `mapstructure:"rules,omitempty" json:"rules,omitempty" validate:"omitempty,gte=1,dive"`
}

// ===============================================================================
// REST API Authorization Config

// PermissionForAPIMethodConfig lists the permissions needed use a method
type PermissionForAPIMethodConfig struct {
	// Method specify the REST method these permissions are associated with. "*" is a wildcard.
	Method string `mapstructure:"method" json:"method" validate:"required,oneof=GET HEAD PUT POST PATCH DELETE OPTIONS *"`
	// Permissions is the list of user permissions allowed to use a method
	Permissions []string `mapstructure:"allowedPermissions" json:"allowedPermissions" validate:"required,gte=1,dive,user_permissions"`
}

// PathAuthorizationConfig a single path authorization specification
type PathAuthorizationConfig struct {
	// PathRegexPattern is the regex for matching against a request URI path
	PathRegexPattern string `mapstructure:"pathPattern" json:"pathPattern" validate:"required"`
	// AllowedMethods is the list of allowed permission for each specified request
	// method that is supportred by this URI. The method "*" functions as a wildcard.
	// If the request method is not explicitly listed here, it may match against "*" if that
	// was defined.
	AllowedMethods []PermissionForAPIMethodConfig `mapstructure:"allowedMethods" json:"allowedMethods" validate:"required,gte=1,dive"`
}

// HostAuthorizationConfig is a group path authorizations for a specific host
type HostAuthorizationConfig struct {
	// Host is the hostname for this group of path authorizers
	Host string `mapstructure:"host" json:"host" validate:"required,fqdn|eq=*"`
	// TargetPaths is the list of path being checked for this host
	TargetPaths []PathAuthorizationConfig `mapstructure:"allowedPaths" json:"allowedPaths" validate:"required,gte=1,dive"`
}

// AuthorizeRequestParamLocConfig defines which HTTP headers to parse to get the parameters of
// a REST request to authorize. It is expected that the component (i.e. a proxy) requesting
// authorization for a request will provide the needed values through these headers when it
// contacts the authorization server.
type AuthorizeRequestParamLocConfig struct {
	// Host is the host / FQDN of the request being authorized
	Host string `mapstructure:"host" json:"host" validate:"required"`
	// Path is the URI path of the request being authorized
	Path string `mapstructure:"path" json:"path" validate:"required"`
	// Method is the HTTP method of the request being authorized
	Method string `mapstructure:"method" json:"method" validate:"required"`
	// UserID is the user ID of the user making the request
	UserID string `mapstructure:"userID" json:"userID" validate:"required"`
	// Username is the username of the user making the request
	Username string `mapstructure:"username" json:"username" validate:"required"`
	// FirstName is the first name / given name of the user making the request
	FirstName string `mapstructure:"firstName" json:"firstName" validate:"required"`
	// LastName is the last name / surname / family name of the user making the request
	LastName string `mapstructure:"lastName" json:"lastName" validate:"required"`
	// Email is the email of the user making the request
	Email string `mapstructure:"email" json:"email" validate:"required"`
}

// UnknownUserActionConfig defines what actions to take when the request being authorized is made
// by an unknown user
type UnknownUserActionConfig struct {
	// AutoAdd set whether automatically record the unknown user during the authorization process
	//
	// Note: This can be dangerous as it could lead to denial-of-service due to resource exhaustion.
	AutoAdd bool `mapstructure:"autoAdd" json:"autoAdd"`
}

// AuthorizationConfig describes the REST API authorization config
type AuthorizationConfig struct {
	// Rules is the list of TargetHostSpec supported by the server. The host of "*"
	// functions as a wildcard. If a request host is not explicitly listed here, it may match
	// against "*" if that was defined.
	Rules []HostAuthorizationConfig `mapstructure:"rules" json:"rules" validate:"required_with=Enabled,dive"`
	// RequestParamLocation sets which HTTP headers to parse to get the parameters of
	// a REST request to authorize. It is expected that the component (i.e. a proxy) requesting
	// authorization for a request will provide the needed values through these headers when it
	// contacts the authorization server.
	RequestParamLocation AuthorizeRequestParamLocConfig `mapstructure:"requestParamHeaders" json:"requestParamHeaders" validate:"required,dive"`
	// UnknownUser sets what actions to take when the request being authorized is made
	// by an unknown user
	UnknownUser UnknownUserActionConfig `mapstructure:"forUnknownUser" json:"forUnknownUser" validate:"required,dive"`
}

// AuthorizationSubmodule defines authorization submodule config
type AuthorizationSubmodule struct {
	APIServerConfig     `mapstructure:",squash"`
	AuthorizationConfig `mapstructure:",squash"`
}

// ===============================================================================
// OpenID Providers

// OpenIDIssuerConfig defines connection parameters to one OpenID issuer
type OpenIDIssuerConfig struct {
	// Issuer is the URL of the OpenID issuer
	Issuer string `json:"issuer" validate:"required,url"`
	// ClientID is the client ID to use during token introspection
	ClientID *string `json:"client_id" validate:"omitempty"`
	// ClientCred is the client credential to use during token introspection
	ClientCred *string `json:"client_cred" validate:"omitempty"`
	// CustomCA if provided, is the custom CA to use for the TLS session with this issuer.
	CustomCA *string `json:"http_tls_ca,omitempty" validate:"omitempty,file"`
	// RequestHostOverride if specified, use this as "Host" header when communicating with issuer
	RequestHostOverride *string `json:"host_override" validate:"omitempty"`
}

// OpenIDClaimsOfInterestConfig sets which claims to parse from a token to get key
// parameters regarding a user.
//
// Depending on the OpenID provider, these claims are present in the ID token, but may
// also be present in the access token; this is the case with KeyCloak.
type OpenIDClaimsOfInterestConfig struct {
	// UserIDClaim is the claim for containing the user ID
	UserIDClaim string `mapstructure:"userID" json:"userID" validate:"required"`
	// UsernameClaim is the claim containing the user Name
	UsernameClaim *string `mapstructure:"username,omitempty" json:"username,omitempty"`
	// FirstNameClaim is the claim containing the first name / given name of the user
	FirstNameClaim *string `mapstructure:"firstName,omitempty" json:"firstName,omitempty"`
	// LastNameClaim is the claim containing the last name / surname / family name of the user
	LastNameClaim *string `mapstructure:"lastName,omitempty" json:"lastName,omitempty"`
	// EmailClaim is the claim containing the email of the user
	EmailClaim *string `mapstructure:"email,omitempty" json:"email,omitempty"`
}

// IntrospectionConfig OAuth2 token introspect operation config
type IntrospectionConfig struct {
	// Enabled whether introspection enabled
	Enabled bool `mapstructure:"enabled" json:"enabled"`
	// ReIntrospectInterval interval (sec) to periodically re-introspect cached tokens
	ReIntrospectInterval int `mapstructure:"recheckIntervalSec" json:"recheck_interval_sec" validate:"gte=30"`
	// CacheCleanInterval interval (sec) to periodically clear expired tokens from cache
	CacheCleanInterval int `mapstructure:"cacheCleanIntervalSec" json:"cache_clean_interval_sec" validate:"gte=30"`
	// CachePurgeInterval interval (sec) to periodically purge the token cache
	CachePurgeInterval int `mapstructure:"cachePurgeIntervalSec" json:"cache_purge_interval_sec" validate:"gte=60"`
}

// AuthenticationConfig describes the REST API authentication config
type AuthenticationConfig struct {
	// TargetAudience if specified, the token must contain an "aud" claim which matches this value.
	TargetAudience *string `mapstructure:"targetAudience,omitempty" json:"target_audience,omitempty" validate:"omitempty"`
	// TargetClaims sets which claims to parse from a token to get key parameters regarding a user.
	TargetClaims OpenIDClaimsOfInterestConfig `mapstructure:"targetClaims" json:"target_claims" validate:"required,dive"`
	// RequestParamLocation sets which HTTP headers to parse to get the parameters of
	// a REST request to authenticate. It is expected that the component (i.e. a proxy) requesting
	// authentication for a request will provide the needed values through these headers when it
	// contacts the authentication server.
	RequestParamLocation AuthenticateRequestParamLocConfig `mapstructure:"requestParamHeaders" json:"requestParamHeaders" validate:"required,dive"`
	// Introspection define OAuth2 token introspect operation config
	Introspection IntrospectionConfig `mapstructure:"introspect" json:"introspect" validate:"required,dive"`
	// Bypass authentication bypass rules
	Bypass *AuthnBypassConfig `mapstructure:"bypass,omitempty" json:"bypass,omitempty" validate:"omitempty,dive"`
}

// AuthenticationSubmodule defines authentication submodule config
type AuthenticationSubmodule struct {
	APIServerConfig      `mapstructure:",squash"`
	AuthenticationConfig `mapstructure:",squash"`
}

// ===============================================================================
// Complete Configuration Structures

// AuthorizationServerConfig is the authorization server config
type AuthorizationServerConfig struct {
	// Metrics metrics framework configuration
	Metrics MetricsConfig `mapstructure:"metrics" json:"metrics" validate:"required,dive"`
	// CustomRegex sets custom regex used by validator for custom field tags
	CustomRegex CustomValidationsConfig `mapstructure:"customValidationRegex" json:"customValidationRegex" validate:"required,dive"`
	// UserManagement are the user management submodule configs
	UserManagement UserManageSubmodule `mapstructure:"userManagement" json:"userManagement" validate:"required,dive"`
	// Authorization are the authorization submodule configs
	Authorization AuthorizationSubmodule `mapstructure:"authorize" json:"authorize" validate:"required,dive"`
	// Authentication are the authentication submodule configs
	Authentication AuthenticationSubmodule `mapstructure:"authenticate" json:"authenticate" validate:"required,dive"`
}

// ===============================================================================

// InstallDefaultAuthorizationServerConfigValues installs default config parameters in viper
func InstallDefaultAuthorizationServerConfigValues() {
	// Default metrics config
	viper.SetDefault("metrics.metricsEndpoint", "/metrics")
	viper.SetDefault("metrics.maxRequests", 4)
	// Default metrics features config
	viper.SetDefault("metrics.features.enableAppMetrics", false)
	// Default metrics HTTP server config
	viper.SetDefault("metrics.service.listenOn", "0.0.0.0")
	viper.SetDefault("metrics.service.appPort", 2001)
	viper.SetDefault("metrics.service.timeoutSecs.read", 60)
	viper.SetDefault("metrics.service.timeoutSecs.write", 60)
	viper.SetDefault("metrics.service.timeoutSecs.idle", 60)

	// Default custom validation REGEX patterns
	viper.SetDefault("customValidationRegex.userID", "^([[:alnum:]]|-|_)+$")
	viper.SetDefault("customValidationRegex.username", "^([[:alnum:]]|-|_)+$")
	viper.SetDefault("customValidationRegex.personalName", "^([[:alnum:]]|-)+$")
	viper.SetDefault("customValidationRegex.roleName", "^([[:alnum:]]|-|_)+$")
	viper.SetDefault("customValidationRegex.permission", "^([[:alnum:]]|-|_|:)+$")

	// Default user management submodule config
	viper.SetDefault("userManagement.enabled", true)
	viper.SetDefault("userManagement.service.listenOn", "0.0.0.0")
	viper.SetDefault("userManagement.service.appPort", 3000)
	viper.SetDefault("userManagement.service.timeoutSecs.read", 60)
	viper.SetDefault("userManagement.service.timeoutSecs.write", 60)
	viper.SetDefault("userManagement.service.timeoutSecs.idle", 600)
	viper.SetDefault("userManagement.apis.requestLogging.logLevel", "warn")
	viper.SetDefault("userManagement.apis.requestLogging.healthLogLevel", "debug")
	viper.SetDefault("userManagement.apis.requestLogging.requestIDHeader", "X-Request-ID")
	viper.SetDefault(
		"userManagement.apis.requestLogging.skipHeaders", []string{
			"WWW-Authenticate", "Authorization", "Proxy-Authenticate", "Proxy-Authorization",
		},
	)
	viper.SetDefault("userManagement.apis.endPoint.pathPrefix", "/")

	// Default authorization submodule config
	viper.SetDefault("authorize.enabled", true)
	viper.SetDefault("authorize.service.listenOn", "0.0.0.0")
	viper.SetDefault("authorize.service.appPort", 3001)
	viper.SetDefault("authorize.service.timeoutSecs.read", 60)
	viper.SetDefault("authorize.service.timeoutSecs.write", 60)
	viper.SetDefault("authorize.service.timeoutSecs.idle", 600)
	viper.SetDefault("authorize.apis.requestLogging.logLevel", "warn")
	viper.SetDefault("authorize.apis.requestLogging.healthLogLevel", "debug")
	viper.SetDefault("authorize.apis.requestLogging.requestIDHeader", "X-Request-ID")
	viper.SetDefault(
		"authorize.apis.requestLogging.skipHeaders", []string{
			"WWW-Authenticate", "Authorization", "Proxy-Authenticate", "Proxy-Authorization",
		},
	)
	viper.SetDefault("authorize.apis.endPoint.pathPrefix", "/")
	viper.SetDefault("authorize.requestParamHeaders.host", "X-Forwarded-Host")
	viper.SetDefault("authorize.requestParamHeaders.path", "X-Forwarded-Uri")
	viper.SetDefault("authorize.requestParamHeaders.method", "X-Forwarded-Method")
	viper.SetDefault("authorize.requestParamHeaders.userID", "X-Caller-UserID")
	viper.SetDefault("authorize.requestParamHeaders.username", "X-Caller-Username")
	viper.SetDefault("authorize.requestParamHeaders.firstName", "X-Caller-Firstname")
	viper.SetDefault("authorize.requestParamHeaders.lastName", "X-Caller-Lastname")
	viper.SetDefault("authorize.requestParamHeaders.email", "X-Caller-Email")

	// Default authentication submodule config
	viper.SetDefault("authenticate.enabled", false)
	viper.SetDefault("authenticate.service.listenOn", "0.0.0.0")
	viper.SetDefault("authenticate.service.appPort", 3002)
	viper.SetDefault("authenticate.service.timeoutSecs.read", 60)
	viper.SetDefault("authenticate.service.timeoutSecs.write", 60)
	viper.SetDefault("authenticate.service.timeoutSecs.idle", 600)
	viper.SetDefault("authenticate.apis.requestLogging.logLevel", "warn")
	viper.SetDefault("authenticate.apis.requestLogging.healthLogLevel", "debug")
	viper.SetDefault("authenticate.apis.requestLogging.requestIDHeader", "X-Request-ID")
	viper.SetDefault(
		"authenticate.apis.requestLogging.skipHeaders", []string{
			"WWW-Authenticate", "Authorization", "Proxy-Authenticate", "Proxy-Authorization",
		},
	)
	viper.SetDefault("authenticate.apis.endPoint.pathPrefix", "/")
	viper.SetDefault("authenticate.targetClaims.userID", "sub")
	viper.SetDefault("authenticate.requestParamHeaders.host", "X-Forwarded-Host")
	viper.SetDefault("authenticate.requestParamHeaders.path", "X-Forwarded-Uri")
	viper.SetDefault("authenticate.requestParamHeaders.method", "X-Forwarded-Method")
	viper.SetDefault("authenticate.introspect.enabled", false)
	viper.SetDefault("authenticate.introspect.recheckIntervalSec", 300)
	viper.SetDefault("authenticate.introspect.cacheCleanIntervalSec", 3600)
	viper.SetDefault("authenticate.introspect.cachePurgeIntervalSec", 43200)
}
