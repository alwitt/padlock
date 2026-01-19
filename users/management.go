package users

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"sync"

	"github.com/alwitt/goutils"
	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/models"
	"github.com/apex/log"
)

// managementImpl implements Management
type managementImpl struct {
	goutils.Component
	// db the client object for interacting with the database
	db models.ManagementDBClient
	// roles is the roles provided through configurations
	roles map[string]common.UserRoleConfig
	// rolesLock is a mutex to control access to roles
	rolesLock *sync.RWMutex
}

/*
CreateManagement defines a new Management

	@param db models.ManagementDBClient - the DB client object
	@return instance of Management
*/
func CreateManagement(db models.ManagementDBClient) (Management, error) {
	logTags := log.Fields{"module": "user", "component": "management"}
	return &managementImpl{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
				common.ModifyLogMetadataByAccessAuthorizeParam,
			},
		},
		db:        db,
		roles:     make(map[string]common.UserRoleConfig),
		rolesLock: &sync.RWMutex{},
	}, nil
}

/*
Ready checks whether the client is ready for use.

	@return nil if ready, or an error otherwise
*/
func (m *managementImpl) Ready() error {
	return m.db.Ready()
}

// ------------------------------------------------------------------------------------
// Role Management

/*
AlignRolesWithConfig aligns the role entries on record with the configuration provided

	@param ctxt context.Context - context calling this API
	@param configuredRoles configuredRoles map[string]common.UserRoleConfig - the set of
	configured roles
	@return whether successful
*/
func (m *managementImpl) AlignRolesWithConfig(
	ctxt context.Context, configuredRoles map[string]common.UserRoleConfig,
) error {
	m.rolesLock.Lock()
	defer m.rolesLock.Unlock()
	// Update the DB with the new set of roles
	roleNames := []string{}
	for roleName := range configuredRoles {
		roleNames = append(roleNames, roleName)
	}
	if err := m.db.AlignRolesWithConfig(ctxt, roleNames); err != nil {
		log.WithError(err).WithFields(m.LogTags).
			Errorf("Failed to update data role records based on new config")
		return err
	}
	// Make a deep copy of the new roles
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&configuredRoles); err != nil {
		log.WithError(err).WithFields(m.LogTags).
			Error("Failed to convert new roles into bytes.Buffer")
		return err
	}
	var t map[string]common.UserRoleConfig
	if err := gob.NewDecoder(bytes.NewBuffer(buf.Bytes())).Decode(&t); err != nil {
		log.WithError(err).WithFields(m.LogTags).
			Error("Failed bytes.Buffer of new roles back to map")
		return err
	}
	m.roles = t
	return nil
}

/*
ListAllRoles query for the list of known roles on record

	@param ctxt context.Context - context calling this API
	@return the list roles on record
*/
func (m *managementImpl) ListAllRoles(_ context.Context) (
	map[string]common.UserRoleConfig, error,
) {
	m.rolesLock.RLock()
	defer m.rolesLock.RUnlock()
	return m.roles, nil
}

/*
GetRole query for a particular role on record

	@param ctxt context.Context - context calling this API
	@param role string - the role
	@return that role
*/
func (m *managementImpl) GetRole(_ context.Context, role string) (common.UserRoleConfig, error) {
	m.rolesLock.RLock()
	defer m.rolesLock.RUnlock()
	roleInfo, ok := m.roles[role]
	if !ok {
		return common.UserRoleConfig{}, fmt.Errorf("role %s is unknown", role)
	}
	return roleInfo, nil
}

/*
GetRoleWithLinkedUsers query for a particular role on record along with its associated users

	@param ctxt context.Context - context calling this API
	@param role string - the role
	@return that role, and its associated users.
*/
func (m *managementImpl) GetRoleWithLinkedUsers(ctxt context.Context, role string) (
	common.UserRoleConfig, []models.UserInfo, error,
) {
	m.rolesLock.RLock()
	defer m.rolesLock.RUnlock()
	roleInfo, ok := m.roles[role]
	if !ok {
		return common.UserRoleConfig{}, nil, fmt.Errorf("role %s is unknown", role)
	}
	// Read from DB for the users
	users, err := m.db.GetUsersOfRole(ctxt, role)
	if err != nil {
		log.WithError(err).WithFields(m.LogTags).Errorf("Failed to fetch users of role %s", role)
		return common.UserRoleConfig{}, nil, err
	}
	return roleInfo, users, nil
}

// ------------------------------------------------------------------------------------
// User Management

/*
DefineUser define a user entry with roles

	@param ctxt context.Context - context calling this API
	@param config UserConfig - user config
	@param roles []string - roles for this user
	@return whether successful
*/
func (m *managementImpl) DefineUser(
	ctxt context.Context, config models.UserConfig, roles []string,
) error {
	m.rolesLock.RLock()
	defer m.rolesLock.RUnlock()
	// Verify that the roles actually exist
	for _, aRole := range roles {
		if _, ok := m.roles[aRole]; !ok {
			return fmt.Errorf("user %s is referring to an unknown role %s", config.UserID, aRole)
		}
	}
	// Define the user
	if err := m.db.DefineUser(ctxt, config, roles); err != nil {
		log.WithError(err).WithFields(m.LogTags).Errorf("Failed to define new user %s", config.UserID)
		return err
	}
	return nil
}

// readPermissionSetOfRoles is a helper function to get a set of permission for a list of roles
func (m *managementImpl) readPermissionSetOfRoles(roles []string) map[string]bool {
	permissions := map[string]bool{}
	for _, aRole := range roles {
		if roleInfo, ok := m.roles[aRole]; ok {
			// Return only the unique permissions
			for _, onePerm := range roleInfo.AssignedPermissions {
				permissions[onePerm] = true
			}
		}
	}
	return permissions
}

/*
GetUser query for a user by ID

	@param ctxt context.Context - context calling this API
	@param id string - user entry ID
	@return the user information
*/
func (m *managementImpl) GetUser(ctxt context.Context, id string) (
	UserDetailsWithPermission, error,
) {
	m.rolesLock.RLock()
	defer m.rolesLock.RUnlock()
	// Fetch user
	userInfo, err := m.db.GetUser(ctxt, id)
	if err != nil {
		log.WithError(err).WithFields(m.LogTags).Errorf("Failed to read user %s details", id)
		return UserDetailsWithPermission{}, err
	}
	// Translate the user roles into permissions
	result := UserDetailsWithPermission{
		UserDetails: userInfo, AssociatedPermission: make([]string, 0),
	}
	for onePerm := range m.readPermissionSetOfRoles(userInfo.Roles) {
		result.AssociatedPermission = append(result.AssociatedPermission, onePerm)
	}
	return result, nil
}

/*
DoesUserHavePermission checks whether a particular user has at least one of the allowed permissions.

	@param ctxt context.Context - context calling this API
	@param id string - user entry ID
	@param allowedPermissions []string - list of allowed permissions
	@return whether the user has at least one of the allowed permissions.
*/
func (m *managementImpl) DoesUserHavePermission(
	ctxt context.Context, id string, allowedPermissions []string,
) (bool, error) {
	m.rolesLock.RLock()
	defer m.rolesLock.RUnlock()
	// Fetch user
	userInfo, err := m.db.GetUser(ctxt, id)
	if err != nil {
		log.WithError(err).WithFields(m.LogTags).Errorf("Failed to read user %s details", id)
		return false, err
	}
	// Translate the user roles into permissions
	permissions := m.readPermissionSetOfRoles(userInfo.Roles)
	for _, checkPermission := range allowedPermissions {
		if _, ok := permissions[checkPermission]; ok {
			return true, nil
		}
	}
	return false, nil
}

/*
ListAllUsers query for all users in system

	@param ctxt context.Context - context calling this API
	@return the list of users in system
*/
func (m *managementImpl) ListAllUsers(ctxt context.Context) ([]models.UserInfo, error) {
	return m.db.ListAllUsers(ctxt)
}

/*
DeleteUser deletes a user

	@param ctxt context.Context - context calling this API
	@param id string - user entry ID
	@return whether successful
*/
func (m *managementImpl) DeleteUser(ctxt context.Context, id string) error {
	return m.db.DeleteUser(ctxt, id)
}

/*
UpdateUser update the parameters for a user

	@param ctxt context.Context - context calling this API
	@param id string - user entry ID
	@param newConfig UserConfig - new user config
	@return whether successful
*/
func (m *managementImpl) UpdateUser(
	ctxt context.Context, id string, newConfig models.UserConfig,
) error {
	return m.db.UpdateUser(ctxt, id, newConfig)
}

/*
AddRolesToUser add new roles to a user

	@param ctxt context.Context - context calling this API
	@param id string - user entry ID
	@param newRoles []string - new roles for this user
	@return whether successful
*/
func (m *managementImpl) AddRolesToUser(ctxt context.Context, id string, newRoles []string) error {
	m.rolesLock.RLock()
	defer m.rolesLock.RUnlock()
	// Verify that the roles actually exist
	for _, aRole := range newRoles {
		if _, ok := m.roles[aRole]; !ok {
			return fmt.Errorf("can't add an unknown role %s to user %s", aRole, id)
		}
	}
	return m.db.AddRolesToUser(ctxt, id, newRoles)
}

/*
SetUserRoles change the roles of a user

	@param ctxt context.Context - context calling this API
	@param id string - user entry ID
	@param newRoles []string - new roles for this user
	@return whether successful
*/
func (m *managementImpl) SetUserRoles(ctxt context.Context, id string, newRoles []string) error {
	m.rolesLock.RLock()
	defer m.rolesLock.RUnlock()
	// Verify that the roles actually exist
	for _, aRole := range newRoles {
		if _, ok := m.roles[aRole]; !ok {
			return fmt.Errorf("can't add an unknown role %s to user %s", aRole, id)
		}
	}
	return m.db.SetUserRoles(ctxt, id, newRoles)
}

/*
RemoveRolesFromUser remove roles from user

	@param ctxt context.Context - context calling this API
	@param id string - user entry ID
	@param roles []string - roles to remove from user
	@return whether successful
*/
func (m *managementImpl) RemoveRolesFromUser(
	ctxt context.Context, id string, roles []string,
) error {
	m.rolesLock.RLock()
	defer m.rolesLock.RUnlock()
	// Verify that the roles actually exist
	for _, aRole := range roles {
		if _, ok := m.roles[aRole]; !ok {
			return fmt.Errorf("can't delete an unknown role %s from user %s", aRole, id)
		}
	}
	return m.db.RemoveRolesFromUser(ctxt, id, roles)
}
