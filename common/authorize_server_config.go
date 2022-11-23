package common

import (
	"encoding/json"
	"fmt"

	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
)

/*
Validate the authorization server config

	@return nil if valid, or an error
*/
func (c AuthorizationServerConfig) Validate() error {
	validate := validator.New()

	// Validate the custom regex section first
	if err := validate.Struct(&c.CustomRegex); err != nil {
		log.WithError(err).Errorf("Custom validator support not defined")
		return err
	}

	// Short circuit if authorization server not enabled
	if !c.Authorization.Enabled {
		return nil
	}

	// Create a custom validator
	customValidate, err := c.CustomRegex.DefineCustomFieldValidator()
	if err != nil {
		log.WithError(err).Errorf("Unable to define custom validator support")
		return err
	}
	if err := customValidate.RegisterWithValidator(validate); err != nil {
		log.WithError(err).Errorf("Unable to update validator with custom tags")
		return err
	}

	// Perform basic validation
	if err := validate.Struct(&c); err != nil {
		log.WithError(err).Errorf("General config parse failure")
		return err
	}

	// Validate roles
	type roleKeyValidate struct {
		Roles []string `json:"defined_roles" validate:"required,gte=1,dive,role_name"`
	}
	allRoles := roleKeyValidate{Roles: make([]string, 0)}
	availablePermissions := map[string]bool{}
	for roleName, roleInfo := range c.UserManagement.AvailableRoles {
		allRoles.Roles = append(allRoles.Roles, roleName)
		seenPermission := map[string]bool{}
		for _, permission := range roleInfo.AssignedPermissions {
			if _, ok := seenPermission[permission]; ok {
				msg := fmt.Sprintf("Role %s already assigned permission %s", roleName, permission)
				log.Error(msg)
				return fmt.Errorf(msg)
			}
			availablePermissions[permission] = true
		}
	}
	if err := validate.Struct(&allRoles); err != nil {
		t, _ := json.Marshal(&allRoles)
		log.WithError(err).Errorf("Roles config parse failure: %s", t)
		return err
	}

	// Verify hosts defined are all unique
	seenHost := map[string]bool{}
	for _, hostAuthEntry := range c.Authorization.Rules {
		if _, ok := seenHost[hostAuthEntry.Host]; ok {
			msg := fmt.Sprintf("Host %s already defined", hostAuthEntry.Host)
			log.Errorf(msg)
			return fmt.Errorf(msg)
		}
		seenHost[hostAuthEntry.Host] = true
		// Verify path defined are all unique
		seenPathRegex := map[string]bool{}
		for _, pathAuthEntry := range hostAuthEntry.TargetPaths {
			if _, ok := seenPathRegex[pathAuthEntry.PathRegexPattern]; ok {
				msg := fmt.Sprintf(
					"Host %s Path %s already defined", hostAuthEntry.Host, pathAuthEntry.PathRegexPattern,
				)
				log.Errorf(msg)
				return fmt.Errorf(msg)
			}
			seenPathRegex[pathAuthEntry.PathRegexPattern] = true
			// Verify method defined are all unique
			seenMethod := map[string]bool{}
			for _, methodEntry := range pathAuthEntry.AllowedMethods {
				if _, ok := seenMethod[methodEntry.Method]; ok {
					msg := fmt.Sprintf(
						"Method %s Host %s Path %s already defined",
						methodEntry.Method,
						hostAuthEntry.Host,
						pathAuthEntry.PathRegexPattern,
					)
					log.Errorf(msg)
					return fmt.Errorf(msg)
				}
				seenMethod[methodEntry.Method] = true
				seenPermission := map[string]bool{}
				// Verify the permission allowed for this method is actually supported
				for _, permission := range methodEntry.Permissions {
					if _, ok := availablePermissions[permission]; !ok {
						log.Errorf("Permission %s is not defined", permission)
						return fmt.Errorf("permission %s is not defined", permission)
					}
					// Verify the permission list contain no duplicates
					if _, ok := seenPermission[permission]; ok {
						msg := fmt.Sprintf(
							"Permission %s ==> Method %s Host %s Path %s already defined",
							permission,
							methodEntry.Method,
							hostAuthEntry.Host,
							pathAuthEntry.PathRegexPattern,
						)
						log.Errorf(msg)
						return fmt.Errorf(msg)
					}
					seenPermission[permission] = true
				}
			}
		}
	}

	return nil
}
