// Package users - user management package for authorization system
package users

import (
	"context"

	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/models"
)

// UserDetailsWithPermission extends models.UserDetails with additional information that
// users associated permissions
type UserDetailsWithPermission struct {
	models.UserDetails
	// AssociatedPermission list of permissions the user has based on the roles associated with
	// the user
	AssociatedPermission []string
}

// Management is user / role manager
type Management interface {
	/*
		Ready checks whether the client is ready for use.

		 @return nil if ready, or an error otherwise
	*/
	Ready() error

	// ------------------------------------------------------------------------------------
	// Role Management

	/*
		AlignRolesWithConfig aligns the role entries on record with the configuration provided

		 @param ctxt context.Context - context calling this API
		 @param configuredRoles configuredRoles map[string]common.UserRoleConfig - the set of
		 configured roles
		 @return whether successful
	*/
	AlignRolesWithConfig(
		ctxt context.Context, configuredRoles map[string]common.UserRoleConfig,
	) error

	/*
		ListAllRoles query for the list of known roles on record

		 @param ctxt context.Context - context calling this API
		 @return the list roles on record
	*/
	ListAllRoles(ctxt context.Context) (map[string]common.UserRoleConfig, error)

	/*
		GetRole query for a particular role on record

		 @param ctxt context.Context - context calling this API
		 @param role string - the role
		 @return that role
	*/
	GetRole(ctxt context.Context, role string) (common.UserRoleConfig, error)

	/*
		GetRoleWithLinkedUsers query for a particular role on record along with its associated users

		 @param ctxt context.Context - context calling this API
		 @param role string - the role
		 @return that role, and its associated users.
	*/
	GetRoleWithLinkedUsers(ctxt context.Context, role string) (
		common.UserRoleConfig, []models.UserInfo, error,
	)

	// ------------------------------------------------------------------------------------
	// User Management

	/*
		DefineUser define a user entry with roles

		 @param ctxt context.Context - context calling this API
		 @param config UserConfig - user config
		 @param roles []string - roles for this user
		 @return whether successful
	*/
	DefineUser(ctxt context.Context, config models.UserConfig, roles []string) error

	/*
		GetUser query for a user by ID

		 @param ctxt context.Context - context calling this API
		 @param id string - user entry ID
		 @return the user information
	*/
	GetUser(ctxt context.Context, id string) (UserDetailsWithPermission, error)

	/*
		DoesUserHavePermission checks whether a particular user has at least one of the allowed
		permissions.

		 @param ctxt context.Context - context calling this API
		 @param id string - user entry ID
		 @param allowedPermissions []string - list of allowed permissions
		 @return whether the user has at least one of the allowed permissions.
	*/
	DoesUserHavePermission(
		ctxt context.Context, id string, allowedPermissions []string,
	) (bool, error)

	/*
		ListAllUsers query for all users in system

		 @param ctxt context.Context - context calling this API
		 @return the list of users in system
	*/
	ListAllUsers(ctxt context.Context) ([]models.UserInfo, error)

	/*
		DeleteUser deletes a user

		 @param ctxt context.Context - context calling this API
		 @param id string - user entry ID
		 @return whether successful
	*/
	DeleteUser(ctxt context.Context, id string) error

	/*
		UpdateUser update the parameters for a user

		 @param ctxt context.Context - context calling this API
		 @param id string - user entry ID
		 @param newConfig UserConfig - new user config
		 @return whether successful
	*/
	UpdateUser(ctxt context.Context, id string, newConfig models.UserConfig) error

	/*
		AddRolesToUser add new roles to a user

		 @param ctxt context.Context - context calling this API
		 @param id string - user entry ID
		 @param newRoles []string - new roles for this user
		 @return whether successful
	*/
	AddRolesToUser(ctxt context.Context, id string, newRoles []string) error

	/*
		SetUserRoles change the roles of a user

		 @param ctxt context.Context - context calling this API
		 @param id string - user entry ID
		 @param newRoles []string - new roles for this user
		 @return whether successful
	*/
	SetUserRoles(ctxt context.Context, id string, newRoles []string) error

	/*
		RemoveRolesFromUser remove roles from user

		 @param ctxt context.Context - context calling this API
		 @param id string - user entry ID
		 @param roles []string - roles to remove from user
		 @return whether successful
	*/
	RemoveRolesFromUser(ctxt context.Context, id string, roles []string) error
}
