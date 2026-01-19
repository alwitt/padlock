package models

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alwitt/goutils"
	"github.com/alwitt/padlock/common"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// dbUser is a DB entry recording a user
type dbUser struct {
	// ID the DB table entry ID
	ID uint `json:"id" gorm:"primaryKey"`
	// Roles is the list roles assigned to the user
	Roles []dbRole `gorm:"many2many:user_roles;"`
	UserInfo
}

// String is toString for userInfo
func (e dbUser) String() string {
	if e.Username != nil {
		return fmt.Sprintf("'USER %s[%s]'", e.UserID, *e.Username)
	}
	return fmt.Sprintf("'USER %s'", e.UserID)
}

// dbRole is a DB entry recording an in-use user role
type dbRole struct {
	// ID the DB table entry ID
	ID uint `json:"id" gorm:"primaryKey"`
	// CreatedAt is when the table entry is created
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the table entry was last updated
	UpdatedAt time.Time `json:"updated_at"`
	// RoleName is the role's name
	RoleName string `json:"role_name" gorm:"uniqueIndex" validate:"required,role_name"`
	// Users is the list of users with this role
	Users []dbUser `gorm:"many2many:user_roles;"`
}

// String is toString for roleInfo
func (e dbRole) String() string {
	return fmt.Sprintf("'ROLE %s'", e.RoleName)
}

// ManagementDBClient is the DB client for managing user and roles
type ManagementDBClient interface {
	/*
		Ready checks whether the client is ready for use.

		 @return nil if ready, or an error otherwise
	*/
	Ready() error

	// ------------------------------------------------------------------------------------
	// Role Management
	//
	// Though the DB is recording roles, the role entries are meant to reflect the roles
	// defined through the application configuration.

	/*
		AlignRolesWithConfig aligns the role entries in the DB with the configuration provided

		 @param ctxt context.Context - context calling this API
		 @param configuredRoles []string - the list of configured roles
		 @return whether successful
	*/
	AlignRolesWithConfig(ctxt context.Context, configuredRoles []string) error

	/*
		ListAllRoles query for the list of known roles within the DB

		 @param ctxt context.Context - context calling this API
		 @return the list roles in the DB
	*/
	ListAllRoles(ctxt context.Context) ([]string, error)

	/*
		GetUsersOfRole query for the list of users which have that role.

		 @param ctxt context.Context - context calling this API
		 @param role string - the role
		 @return the list of users
	*/
	GetUsersOfRole(ctxt context.Context, role string) ([]UserInfo, error)

	// ------------------------------------------------------------------------------------
	// User Management

	/*
		DefineUser define a user entry with roles

		 @param ctxt context.Context - context calling this API
		 @param config UserConfig - user config
		 @param roles []string - roles for this user
		 @return whether successful
	*/
	DefineUser(ctxt context.Context, config UserConfig, roles []string) error

	/*
		GetUser query for a user by ID

		 @param ctxt context.Context - context calling this API
		 @param id string - user entry ID
		 @return the user information
	*/
	GetUser(ctxt context.Context, id string) (UserDetails, error)

	/*
		ListAllUsers query for all users in system

		 @param ctxt context.Context - context calling this API
		 @return the list of users in system
	*/
	ListAllUsers(ctxt context.Context) ([]UserInfo, error)

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
	UpdateUser(ctxt context.Context, id string, newConfig UserConfig) error

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

// ======================================================================================

// roleManagementDBClientImpl implements ManagementDBClient
type managementDBClientImpl struct {
	goutils.Component
	db                    *gorm.DB
	validate              *validator.Validate
	customValidateSupport common.CustomFieldValidator
}

/*
CreateManagementDBClient create a new DB client

	@param db *gorm.DB - GORM DB client
	@return client
*/
func CreateManagementDBClient(db *gorm.DB, validateSupport common.CustomFieldValidator) (
	ManagementDBClient, error,
) {
	validate := validator.New()
	if err := validateSupport.RegisterWithValidator(validate); err != nil {
		return nil, err
	}

	logTags := log.Fields{"module": "models", "component": "user-db-client"}

	// Prepare the models
	if err := db.AutoMigrate(&dbUser{}); err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(&dbRole{}); err != nil {
		return nil, err
	}

	return &managementDBClientImpl{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
				common.ModifyLogMetadataByAccessAuthorizeParam,
			},
		},
		db:                    db,
		validate:              validate,
		customValidateSupport: validateSupport,
	}, nil
}

// --------------------------------------------------------------------------------------

/*
Ready checks whether the client is ready for use.

	@return nil if ready, or an error otherwise
*/
func (c *managementDBClientImpl) Ready() error {
	var users []dbUser
	if tmp := c.db.Limit(1).Find(&users); tmp.Error != nil {
		return tmp.Error
	}
	return nil
}

// ------------------------------------------------------------------------------------
// Role Management
//
// Though the DB is recording roles, the role entries are meant to reflect the roles
// defined through the application configuration.

/*
AlignRolesWithConfig aligns the role entries in the DB with the configuration provided

	@param ctxt context.Context - context calling this API
	@param configuredRoles []string - the list of configured roles
	@return whether successful
*/
func (c *managementDBClientImpl) AlignRolesWithConfig(
	ctxt context.Context, configuredRoles []string,
) error {
	logTags := c.GetLogTagsForContext(ctxt)
	return c.db.Transaction(func(tx *gorm.DB) error {
		var roles []dbRole
		if tmp := tx.Preload("Users").Find(&roles); tmp.Error != nil {
			log.WithError(tmp.Error).WithFields(logTags).Errorf("Failed to list all roles")
			return tmp.Error
		}

		expectedRoles := map[string]bool{}
		for _, aRole := range configuredRoles {
			expectedRoles[aRole] = true
		}
		currentRoles := map[string]dbRole{}
		for _, aRole := range roles {
			currentRoles[aRole.RoleName] = aRole
		}

		var removeRoles []dbRole
		var addRoles []string

		// Determine the roles which needs to be removed
		for roleName, entry := range currentRoles {
			_, ok := expectedRoles[roleName]
			if !ok {
				removeRoles = append(removeRoles, entry)
			}
		}
		// Determine the roles which needs to be added
		for roleName := range expectedRoles {
			_, ok := currentRoles[roleName]
			if !ok {
				addRoles = append(addRoles, roleName)
			}
		}

		// Delete extra roles
		deleteRoleNames := []string{}
		for _, entry := range removeRoles {
			deleteRoleNames = append(deleteRoleNames, entry.RoleName)
			// Clear the associations with user entries
			if len(entry.Users) > 0 {
				if err := tx.Model(&entry).Association("Users").Clear(); err != nil {
					log.WithError(err).WithFields(logTags).
						Errorf("Unable to clear associations for %s", entry.String())
					return err
				}
			}
		}
		if err := c.deleteRoles(ctxt, tx, deleteRoleNames); err != nil {
			return err
		}

		// Add the missing roles
		if _, err := c.createRoles(ctxt, tx, addRoles); err != nil {
			return err
		}

		log.WithFields(logTags).Infof("Synced up the role entries with configuration")
		return nil
	})
}

/*
createRoles create a set of new roles

	@param ctxt context.Context - context calling this API
	@param tx *gorm.DB - DB session object
	@param roles []string - list of roles to create for
	@return the set of role objects
*/
func (c *managementDBClientImpl) createRoles(ctxt context.Context, tx *gorm.DB, roles []string) (
	[]dbRole, error,
) {
	if len(roles) == 0 {
		return nil, nil
	}
	var results []dbRole
	logTags := c.GetLogTagsForContext(ctxt)
	return results, tx.Transaction(func(tx *gorm.DB) error {
		entries := []dbRole{}
		for _, newRole := range roles {
			newEntry := dbRole{RoleName: newRole}
			if err := c.validate.Struct(&newEntry); err != nil {
				log.WithError(err).WithFields(logTags).Errorf("Role %s not valid", newRole)
				return err
			}
			entries = append(entries, newEntry)
		}
		if tmp := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&entries); tmp.Error != nil {
			t, _ := json.Marshal(&roles)
			log.WithError(tmp.Error).WithFields(logTags).Errorf("Failed to insert new roles %s", t)
			return tmp.Error
		}
		if tmp := tx.Where("role_name", roles).Find(&results); tmp.Error != nil {
			t, _ := json.Marshal(&roles)
			log.WithError(tmp.Error).WithFields(logTags).Errorf("Failed to read back entries for %s", t)
			return tmp.Error
		}
		return nil
	})
}

/*
deleteRoles delete a set of roles

	@param ctxt context.Context - context calling this API
	@param tx *gorm.DB - DB session object
	@param roles []string - list of roles to delete
	@return whether successful
*/
func (c *managementDBClientImpl) deleteRoles(
	ctxt context.Context, tx *gorm.DB, roles []string,
) error {
	if len(roles) == 0 {
		return nil
	}
	logTags := c.GetLogTagsForContext(ctxt)
	return tx.Transaction(func(tx *gorm.DB) error {
		if tmp := tx.Where("role_name", roles).Delete(dbRole{}); tmp.Error != nil {
			t, _ := json.Marshal(&roles)
			log.WithError(tmp.Error).WithFields(logTags).Errorf("Failed to delete entries for %s", t)
			return tmp.Error
		}
		return nil
	})
}

/*
ListAllRoles query for the list of known roles within the DB

	@param ctxt context.Context - context calling this API
	@return the list roles in the DB
*/
func (c *managementDBClientImpl) ListAllRoles(ctxt context.Context) ([]string, error) {
	var result []string
	logTags := c.GetLogTagsForContext(ctxt)
	return result, c.db.Transaction(func(tx *gorm.DB) error {
		var allRoles []dbRole
		if tmp := tx.Find(&allRoles); tmp.Error != nil {
			log.WithFields(logTags).Errorf("Unable to query all user roles")
			return tmp.Error
		}
		for _, entry := range allRoles {
			result = append(result, entry.RoleName)
		}
		return nil
	})
}

/*
GetUsersOfRole query for the list of users which have that role.

	@param ctxt context.Context - context calling this API
	@param role string - the role
	@return the list of users
*/
func (c *managementDBClientImpl) GetUsersOfRole(ctxt context.Context, role string) (
	[]UserInfo, error,
) {
	var result []UserInfo
	logTags := c.GetLogTagsForContext(ctxt)
	return result, c.db.Transaction(func(tx *gorm.DB) error {
		var theRole dbRole
		if tmp := tx.Where(&dbRole{RoleName: role}).Preload("Users").First(&theRole); tmp.Error != nil {
			log.WithError(tmp.Error).WithFields(logTags).Errorf("Couldn't select role %s", role)
			return tmp.Error
		}
		// Copy out the user for returning
		for _, userEntry := range theRole.Users {
			result = append(result, userEntry.UserInfo)
		}
		return nil
	})
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
func (c *managementDBClientImpl) DefineUser(
	ctxt context.Context, config UserConfig, roles []string,
) error {
	logTags := c.GetLogTagsForContext(ctxt)
	return c.db.Transaction(func(tx *gorm.DB) error {
		if err := c.validate.Struct(&config); err != nil {
			log.WithError(err).WithFields(logTags).Errorf("User %s has invalid params", config.UserID)
			return err
		}
		newEntry := dbUser{
			UserInfo: UserInfo{
				UserConfig: config,
			},
		}
		if tmp := tx.Create(&newEntry); tmp.Error != nil {
			log.WithError(tmp.Error).WithFields(logTags).
				Errorf("Failed to create user %s", config.UserID)
			return tmp.Error
		}
		// Associate the roles as well
		roleEntries, err := c.createRoles(ctxt, tx, roles)
		if err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Failed to define %s roles", newEntry.String())
			return err
		}
		for _, roleEntry := range roleEntries {
			if err := tx.Model(&newEntry).Association("Roles").Append(&roleEntry); err != nil {
				log.WithError(err).WithFields(logTags).
					Errorf("Failed to add %s to %s", roleEntry.String(), newEntry.String())
				return err
			}
		}
		return nil
	})
}

/*
fetchUser reads a single user entry

	@param tx *gorm.DB - the DB client
	@param id string - user entry ID
	@return the user entry from DB
*/
func (c *managementDBClientImpl) fetchUser(tx *gorm.DB, id string) (dbUser, error) {
	var userEntry dbUser
	tmp := tx.Where(
		&dbUser{UserInfo: UserInfo{UserConfig: UserConfig{UserID: id}}},
	).First(&userEntry)
	return userEntry, tmp.Error
}

/*
fetchUserWithRoles reads a single user entry with it associated roles

	@param tx *gorm.DB - the DB client
	@param id string - user entry ID
	@return the user entry from DB
*/
func (c *managementDBClientImpl) fetchUserWithRoles(tx *gorm.DB, id string) (dbUser, error) {
	var userEntry dbUser
	tmp := tx.Where(
		&dbUser{UserInfo: UserInfo{UserConfig: UserConfig{UserID: id}}},
	).Preload("Roles").First(&userEntry)
	return userEntry, tmp.Error
}

/*
GetUser query for a user by ID

	@param ctxt context.Context - context calling this API
	@param id string - user entry ID
	@return the user information
*/
func (c *managementDBClientImpl) GetUser(ctxt context.Context, id string) (UserDetails, error) {
	var result UserDetails
	logTags := c.GetLogTagsForContext(ctxt)
	return result, c.db.Transaction(func(tx *gorm.DB) error {
		userEntry, err := c.fetchUserWithRoles(tx, id)
		if err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Failed to query user %s", id)
			return err
		}
		result.UserInfo = userEntry.UserInfo
		result.Roles = make([]string, len(userEntry.Roles))
		for idx, roleEntry := range userEntry.Roles {
			result.Roles[idx] = roleEntry.RoleName
		}
		return nil
	})
}

/*
ListAllUsers query for all users in system

	@param ctxt context.Context - context calling this API
	@return the list of users in system
*/
func (c *managementDBClientImpl) ListAllUsers(ctxt context.Context) ([]UserInfo, error) {
	var result []UserInfo
	logTags := c.GetLogTagsForContext(ctxt)
	return result, c.db.Transaction(func(tx *gorm.DB) error {
		var allUsers []dbUser
		if tmp := tx.Find(&allUsers); tmp.Error != nil {
			log.WithError(tmp.Error).WithFields(logTags).Errorf("Failed to query for all user")
			return tmp.Error
		}
		result = make([]UserInfo, len(allUsers))
		for idx, entry := range allUsers {
			result[idx] = entry.UserInfo
		}
		return nil
	})
}

/*
DeleteUser deletes a user

	@param ctxt context.Context - context calling this API
	@param id string - user entry ID
	@return whether successful
*/
func (c *managementDBClientImpl) DeleteUser(ctxt context.Context, id string) error {
	logTags := c.GetLogTagsForContext(ctxt)
	return c.db.Transaction(func(tx *gorm.DB) error {
		userEntry, err := c.fetchUserWithRoles(tx, id)
		if err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Failed to query user %s", id)
			return err
		}
		// Remove role association of user
		if len(userEntry.Roles) > 0 {
			if err := tx.Model(&userEntry).Association("Roles").Clear(); err != nil {
				log.WithError(err).WithFields(logTags).
					Errorf("Failed to remove roles from %s", userEntry.String())
				return err
			}
		}
		if tmp := tx.Delete(&userEntry); tmp.Error != nil {
			log.WithError(tmp.Error).WithFields(logTags).Errorf("Failed to delete %s", userEntry.String())
			return tmp.Error
		}
		return nil
	})
}

/*
UpdateUser update the parameters for a user

	@param ctxt context.Context - context calling this API
	@param id string - user entry ID
	@param newConfig UserConfig - new user config
	@return whether successful
*/
func (c *managementDBClientImpl) UpdateUser(
	ctxt context.Context, id string, newConfig UserConfig,
) error {
	logTags := c.GetLogTagsForContext(ctxt)
	if id != newConfig.UserID {
		err := fmt.Errorf("update details contains different ID")
		log.WithError(err).WithFields(logTags).Errorf("Updated entry for user %s is invalid", id)
		return err
	}
	return c.db.Transaction(func(tx *gorm.DB) error {
		userEntry, err := c.fetchUser(tx, id)
		if err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Failed to query user %s", id)
			return err
		}
		// Change the core parameters
		userEntry.UserConfig = newConfig
		if err := c.validate.Struct(&userEntry); err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Updated entry for user %s is invalid", id)
			return err
		}
		if tmp := tx.Save(&userEntry); tmp.Error != nil {
			log.WithError(err).WithFields(logTags).Errorf("Failed to update %s", userEntry.String())
			return err
		}
		return nil
	})
}

/*
AddRolesToUser add new roles to a user

	@param ctxt context.Context - context calling this API
	@param id string - user entry ID
	@param newRoles []string - new roles for this user
	@return whether successful
*/
func (c *managementDBClientImpl) AddRolesToUser(
	ctxt context.Context, id string, newRoles []string,
) error {
	logTags := c.GetLogTagsForContext(ctxt)
	return c.db.Transaction(func(tx *gorm.DB) error {
		userEntry, err := c.fetchUserWithRoles(tx, id)
		if err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Failed to query user %s", id)
			return err
		}
		roleEntries, err := c.createRoles(ctxt, tx, newRoles)
		if err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Failed to define %s new roles", userEntry.String())
			return err
		}
		for _, roleEntry := range roleEntries {
			if err := tx.Model(&userEntry).Association("Roles").Append(&roleEntry); err != nil {
				log.WithError(err).WithFields(logTags).
					Errorf("Failed to add %s to %s", roleEntry.String(), userEntry.String())
				return err
			}
		}
		return nil
	})
}

/*
SetUserRoles change the roles of a user

	@param ctxt context.Context - context calling this API
	@param id string - user entry ID
	@param newRoles []string - new roles for this user
	@return whether successful
*/
func (c *managementDBClientImpl) SetUserRoles(
	ctxt context.Context, id string, newRoles []string,
) error {
	logTags := c.GetLogTagsForContext(ctxt)
	return c.db.Transaction(func(tx *gorm.DB) error {
		userEntry, err := c.fetchUserWithRoles(tx, id)
		if err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Failed to query user %s", id)
			return err
		}
		roleEntries, err := c.createRoles(ctxt, tx, newRoles)
		if err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Failed to define %s new roles", userEntry.String())
			return err
		}
		// Clear the current associations
		if err := tx.Model(&userEntry).Association("Roles").Clear(); err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Failed to clear %s roles", userEntry.String())
			return err
		}
		for _, roleEntry := range roleEntries {
			if err := tx.Model(&userEntry).Association("Roles").Append(&roleEntry); err != nil {
				log.WithError(err).WithFields(logTags).
					Errorf("Failed to add %s to %s", roleEntry.String(), userEntry.String())
				return err
			}
		}
		return nil
	})
}

/*
RemoveRolesFromUser remove roles from user

	@param ctxt context.Context - context calling this API
	@param id string - user entry ID
	@param roles []string - roles to remove from user
	@return whether successful
*/
func (c *managementDBClientImpl) RemoveRolesFromUser(
	ctxt context.Context, id string, roles []string,
) error {
	logTags := c.GetLogTagsForContext(ctxt)
	return c.db.Transaction(func(tx *gorm.DB) error {
		rolesAsMap := map[string]bool{}
		for _, role := range roles {
			rolesAsMap[role] = true
		}
		userEntry, err := c.fetchUserWithRoles(tx, id)
		if err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Failed to query user %s", id)
			return err
		}
		// Determine which role entry need to remove
		removeRoles := []dbRole{}
		for _, roleEntry := range userEntry.Roles {
			if _, ok := rolesAsMap[roleEntry.RoleName]; ok {
				removeRoles = append(removeRoles, roleEntry)
			}
		}
		// Remove the extra roles
		if err := tx.Model(&userEntry).Association("Roles").Delete(removeRoles); err != nil {
			t, _ := json.Marshal(roles)
			log.WithError(err).WithFields(logTags).
				Errorf("Failed to delete roles %s from %s", t, userEntry)
			return err
		}
		return nil
	})
}
