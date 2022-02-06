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
// Complete Configuration Structures

// AuthorizationServerConfig is the authorization server config
type AuthorizationServerConfig struct {
	Common    UtilConfigs         `mapstructure:"common" json:"common" validate:"required,dive"`
	Roles     UserRolesConfig     `mapstructure:"role" json:"role" validate:"required,dive"`
	Authorize AuthorizationConfig `mapstructure:"authorize" json:"authorize" validate:"required,dive"`
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
}
