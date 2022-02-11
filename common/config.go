package common

import "github.com/spf13/viper"

// ===============================================================================
// Utility Config

// CustomValidationsConfig provides the custom validation regex patterns
type CustomValidationsConfig struct {
	// UserIDRegex is the regex pattern used to validate a user ID
	UserIDRegex string `mapstructure:"user_id" json:"user_id" validate:"required"`
	// UserNameRegex is the regex pattern used to validate a username
	UserNameRegex string `mapstructure:"username" json:"username" validate:"required"`
	// PersonalNameRegex is the regex pattern used to validate a personal name
	PersonalNameRegex string `mapstructure:"personal_name" json:"personal_name" validate:"required"`
	// RoleNameRegex is the regex pattern used to validate a role name
	RoleNameRegex string `mapstructure:"role_name" json:"role_name" validate:"required"`
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

// UtilConfigs provides common configuration used throughout the system
type UtilConfigs struct {
	ValidationSupport CustomValidationsConfig `mapstructure:"custom_validation_regex" json:"custom_validation_regex" validate:"required,dive"`
}

// ===============================================================================
// User Role Config

// UserRoleConfig a single user role
type UserRoleConfig struct {
	// AssignedPermissions is the list of permissions assigned to a role
	AssignedPermissions []string `mapstructure:"assigned_permissions" json:"assigned_permissions" validate:"required,gte=1,dive,user_permissions"`
}

// UserRolesConfig a group of user roles
type UserRolesConfig struct {
	// AvailableRoles is the set of roles supported by the system
	AvailableRoles map[string]UserRoleConfig `mapstructure:"available_roles" json:"available_roles" validate:"required,gte=1,dive"`
}

// ===============================================================================
// REST API Authorization Config

// PermissionForAPIMethodConfig lists the permissions needed use a method
type PermissionForAPIMethodConfig struct {
	// Method specify the REST method these permissions are associated with. "*" is a wildcard.
	Method string `mapstructure:"method" json:"method" validate:"required,oneof=GET HEAD PUT POST PATCH DELETE OPTIONS *"`
	// Permissions is the list of user permissions allowed to use a method
	Permissions []string `mapstructure:"allowed_permissions" json:"allowed_permissions" validate:"required,gte=1,dive,user_permissions"`
}

// PathAuthorizationConfig a single path authorization specification
type PathAuthorizationConfig struct {
	// PathRegexPattern is the regex for matching against a request URI path
	PathRegexPattern string `mapstructure:"path_pattern" json:"path_pattern" validate:"required"`
	// AllowedMethods is the list of allowed permission for each specified request
	// method that is supportred by this URI. The method "*" functions as a wildcard.
	// If the request method is not explicitly listed here, it may match against "*" if that
	// was defined.
	AllowedMethods []PermissionForAPIMethodConfig `mapstructure:"methods" json:"methods" validate:"required,gte=1,dive"`
}

// HostAuthorizationConfig is a group path authorizations for a specific host
type HostAuthorizationConfig struct {
	// Host is the hostname for this group of path authorizers
	Host string `mapstructure:"host" json:"host" validate:"required,fqdn|eq=*"`
	// TargetPaths is the list of path being checked for this host
	TargetPaths []PathAuthorizationConfig `mapstructure:"paths" json:"paths" validate:"required,gte=1,dive"`
}

// AuthorizationConfig describes the REST API authorization config
type AuthorizationConfig struct {
	// TargetHosts is the list of TargetHostSpec supported by the server. The host of "*"
	// functions as a wildcard. If a request host is not explicitly listed here, it may match
	// against "*" if that was defined.
	TargetHosts []HostAuthorizationConfig `mapstructure:"hosts" json:"hosts" validate:"required,gte=1,dive"`
}

// ===============================================================================
// HTTP Related Config

// HTTPServerConfig defines the HTTP server parameters
type HTTPServerConfig struct {
	// ListenOn is the interface the HTTP server will listen on
	ListenOn string `mapstructure:"listen_on" json:"listen_on" validate:"required,ip"`
	// Port is the port the HTTP server will listen on
	Port uint16 `mapstructure:"listen_port" json:"listen_port" validate:"required,gt=0,lt=65536"`
	// ReadTimeout is the maximum duration for reading the entire
	// request, including the body in seconds. A zero or negative
	// value means there will be no timeout.
	ReadTimeout int `mapstructure:"read_timeout_sec" json:"read_timeout_sec" validate:"gte=0"`
	// WriteTimeout is the maximum duration before timing out
	// writes of the response in seconds. A zero or negative value
	// means there will be no timeout.
	WriteTimeout int `mapstructure:"write_timeout_sec" json:"write_timeout_sec" validate:"gte=0"`
	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled in seconds. If
	// IdleTimeout is zero, the value of ReadTimeout is used. If
	// both are zero, there is no timeout.
	IdleTimeout int `mapstructure:"idle_timeout_sec" json:"idle_timeout_sec" validate:"gte=0"`
}

// HTTPRequestLogging defines HTTP request logging parameters
type HTTPRequestLogging struct {
	// EndOfRequestMessage is the message logged marking end of a request
	EndOfRequestMessage string `mapstructure:"end_of_request_message" json:"end_of_request_message"`
	// DoNotLogHeaders is the list of headers to not include in logging metadata
	DoNotLogHeaders []string `mapstructure:"do_not_log_headers" json:"do_not_log_headers"`
}

// EndpointConfig defines API endpoint config
type EndpointConfig struct {
	// PathPrefix is the end-point path prefix for the APIs
	PathPrefix string `mapstructure:"path_prefix" json:"path_prefix" validate:"required"`
}

// HTTPConfig defines HTTP API / server parameters
type HTTPConfig struct {
	// Enabled whether this API is enabled
	Enabled bool `mapstructure:"enabled" json:"enabled"`
	// Server defines HTTP server parameters
	Server HTTPServerConfig `mapstructure:"server_config" json:"server_config" validate:"required_with=Enabled,dive"`
	// Logging defines operation logging parameters
	Logging HTTPRequestLogging `mapstructure:"logging_config" json:"logging_config" validate:"required_with=Enabled,dive"`
	// Endpoints is the API endpoint config parameters for the management API server
	Endpoints EndpointConfig `mapstructure:"endpoint_config" json:"endpoint_config" validate:"required_with=Enabled,dive"`
}

// APIConfig defines all HTTP API supported
type APIConfig struct {
	// UserAdmin defines user admin API related configs
	UserAdmin HTTPConfig `mapstructure:"user_admin" json:"user_admin" validate:"required,dive"`
}

// ===============================================================================
// Database Config

// DatabaseConfig database related configuration
type DatabaseConfig struct {
	// Host is the DB host
	Host string `mapstructure:"host" json:"host" validate:"required"`
	// DB is the database name
	DB string `json:"db" validate:"required"`
	// User is the database user
	User string `json:"user" validate:"required"`
	// Password is the user password
	Password *string `json:"pw,omitempty"`
}

// ===============================================================================
// Complete Configuration Structures

// AuthorizationServerConfig is the authorization server config
type AuthorizationServerConfig struct {
	Common    UtilConfigs         `mapstructure:"common" json:"common" validate:"required,dive"`
	Roles     UserRolesConfig     `mapstructure:"role" json:"role" validate:"required,dive"`
	Authorize AuthorizationConfig `mapstructure:"authorize" json:"authorize" validate:"required,dive"`
	API       APIConfig           `mapstructure:"api" json:"api" validate:"required,dive"`
}

// ===============================================================================

// InstallDefaultAuthorizationServerConfigValues installs default config parameters in viper
func InstallDefaultAuthorizationServerConfigValues() {
	// Default custom validation REGEX patterns
	viper.SetDefault("common.custom_validation_regex.user_id", "^([[:alnum:]]|-|_)+$")
	viper.SetDefault("common.custom_validation_regex.username", "^([[:alnum:]]|-|_)+$")
	viper.SetDefault("common.custom_validation_regex.personal_name", "^([[:alnum:]]|-)+$")
	viper.SetDefault("common.custom_validation_regex.role_name", "^([[:alnum:]]|-|_)+$")
	viper.SetDefault("common.custom_validation_regex.permission", "^([[:alnum:]]|-|_|:)+$")

	// Default HTTP REST Responder API config
	viper.SetDefault("api.user_admin.enabled", true)
	viper.SetDefault("api.user_admin.server_config.listen_on", "0.0.0.0")
	viper.SetDefault("api.user_admin.server_config.listen_port", 3000)
	viper.SetDefault("api.user_admin.server_config.read_timeout_sec", 60)
	viper.SetDefault("api.user_admin.server_config.write_timeout_sec", 60)
	viper.SetDefault("api.user_admin.server_config.idle_timeout_sec", 600)
	viper.SetDefault("api.user_admin.logging_config.end_of_request_message", "Request Complete")
	viper.SetDefault(
		"api.user_admin.logging_config.do_not_log_headers", []string{
			"WWW-Authenticate", "Authorization", "Proxy-Authenticate", "Proxy-Authorization",
		},
	)
	viper.SetDefault("api.user_admin.endpoint_config.path_prefix", "/")
}
