package users

import (
	"context"
	"fmt"
	"testing"

	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/models"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestManagingRoles(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	dbName := fmt.Sprintf("/tmp/models_test_%s.db", uuid.New().String())
	log.Debugf("Unit-test DB %s", dbName)
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	assert.Nil(err)
	supportMatch, err := common.GetCustomFieldValidator(
		`^[a-zA-Z0-9-]+$`, `^[a-zA-Z0-9-]+$`, `^[a-zA-Z0-9-]+$`, `^[a-zA-Z0-9-]+$`, `^.+$`,
	)
	assert.Nil(err)
	dbClient, err := models.CreateManagementDBClient(db, supportMatch)
	assert.Nil(err)
	assert.Nil(dbClient.Ready())

	uut, err := CreateManagement(dbClient)
	assert.Nil(err)
	assert.Nil(uut.Ready())

	// Case 0: no roles
	{
		roles, err := uut.ListAllRoles(context.Background())
		assert.Nil(err)
		assert.Empty(roles)
		_, err = uut.GetRole(context.Background(), uuid.New().String())
		assert.NotNil(err)
		_, _, err = uut.GetRoleWithLinkedUsers(context.Background(), uuid.New().String())
		assert.NotNil(err)
	}

	roles := make([]string, 4)
	for itr := 0; itr < 4; itr++ {
		roles[itr] = uuid.New().String()
	}

	permissions := make([]string, 3)
	for itr := 0; itr < 3; itr++ {
		permissions[itr] = uuid.New().String()
	}

	type testCase struct {
		testRoles map[string]common.UserRoleConfig
	}

	// Case 1: alter the roles on record
	cases := []testCase{
		{
			testRoles: map[string]common.UserRoleConfig{
				roles[0]: {AssignedPermissions: []string{permissions[0], permissions[1]}},
				roles[1]: {AssignedPermissions: []string{permissions[2]}},
			},
		},
		{
			testRoles: map[string]common.UserRoleConfig{
				roles[0]: {AssignedPermissions: []string{permissions[0]}},
				roles[2]: {AssignedPermissions: []string{permissions[1]}},
			},
		},
		{
			testRoles: map[string]common.UserRoleConfig{
				roles[1]: {AssignedPermissions: permissions},
			},
		},
	}
	for _, oneCase := range cases {
		assert.Nil(uut.AlignRolesWithConfig(context.Background(), oneCase.testRoles))
		rolesInstalled, err := uut.ListAllRoles(context.Background())
		assert.Nil(err)
		assert.Len(rolesInstalled, len(oneCase.testRoles))
		for theRole, permissions := range oneCase.testRoles {
			roleInfo, ok := rolesInstalled[theRole]
			assert.True(ok)
			assert.EqualValues(permissions.AssignedPermissions, roleInfo.AssignedPermissions)
			roleInfo, users, err := uut.GetRoleWithLinkedUsers(context.Background(), theRole)
			assert.Nil(err)
			assert.Empty(users)
			assert.EqualValues(permissions.AssignedPermissions, roleInfo.AssignedPermissions)
		}
	}
}

func TestManagingUsers(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	dbName := fmt.Sprintf("/tmp/models_test_%s.db", uuid.New().String())
	log.Debugf("Unit-test DB %s", dbName)
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	assert.Nil(err)
	supportMatch, err := common.GetCustomFieldValidator(
		`^[a-zA-Z0-9-]+$`, `^[a-zA-Z0-9-]+$`, `^[a-zA-Z0-9-]+$`, `^[a-zA-Z0-9-]+$`, `^.+$`,
	)
	assert.Nil(err)
	dbClient, err := models.CreateManagementDBClient(db, supportMatch)
	assert.Nil(err)
	assert.Nil(dbClient.Ready())

	uut, err := CreateManagement(dbClient)
	assert.Nil(err)
	assert.Nil(uut.Ready())

	roles := make([]string, 4)
	for itr := 0; itr < 4; itr++ {
		roles[itr] = uuid.New().String()
	}

	permissions := make([]string, 3)
	for itr := 0; itr < 3; itr++ {
		permissions[itr] = uuid.New().String()
	}

	testRoles := map[string]common.UserRoleConfig{
		roles[0]: {AssignedPermissions: []string{permissions[0], permissions[1]}},
		roles[1]: {AssignedPermissions: []string{permissions[2]}},
		roles[2]: {AssignedPermissions: []string{permissions[1], permissions[2]}},
	}
	assert.Nil(uut.AlignRolesWithConfig(context.Background(), testRoles))

	// Case 0: no users
	{
		_, err := uut.GetUser(context.Background(), uuid.New().String())
		assert.NotNil(err)
	}

	// Case 1: add user
	user1 := uuid.New().String()
	{
		param := models.UserConfig{UserID: user1}
		assert.Nil(uut.DefineUser(context.Background(), param, []string{roles[0], roles[2]}))
	}
	{
		user, err := uut.GetUser(context.Background(), user1)
		assert.Nil(err)
		assert.Equal(user1, user.UserID)
		assert.EqualValues(roleListToMap([]string{roles[0], roles[2]}), roleListToMap(user.Roles))
		assert.EqualValues(
			roleListToMap([]string{permissions[0], permissions[1], permissions[2]}),
			roleListToMap(user.AssociatedPermission),
		)
	}
	{
		_, users, err := uut.GetRoleWithLinkedUsers(context.Background(), roles[0])
		assert.Nil(err)
		assert.Len(users, 1)
		assert.Equal(user1, users[0].UserID)
	}

	// Case 2: change user roles
	{
		newRoles := []string{roles[1]}
		assert.Nil(uut.AddRolesToUser(context.Background(), user1, newRoles))
	}
	{
		user, err := uut.GetUser(context.Background(), user1)
		assert.Nil(err)
		assert.Equal(user1, user.UserID)
		assert.EqualValues(
			roleListToMap([]string{roles[0], roles[1], roles[2]}), roleListToMap(user.Roles),
		)
		assert.EqualValues(
			roleListToMap([]string{permissions[0], permissions[1], permissions[2]}),
			roleListToMap(user.AssociatedPermission),
		)
	}

	// Case 3: remove a user role
	{
		removeRoles := []string{roles[0]}
		assert.Nil(uut.RemoveRolesFromUser(context.Background(), user1, removeRoles))
	}
	{
		user, err := uut.GetUser(context.Background(), user1)
		assert.Nil(err)
		assert.Equal(user1, user.UserID)
		assert.EqualValues(roleListToMap([]string{roles[1], roles[2]}), roleListToMap(user.Roles))
		assert.EqualValues(
			roleListToMap([]string{permissions[1], permissions[2]}),
			roleListToMap(user.AssociatedPermission),
		)
	}

	// Case 4: use an unknown role
	{
		newRoles := []string{roles[3]}
		assert.NotNil(uut.AddRolesToUser(context.Background(), user1, newRoles))
	}
	{
		user, err := uut.GetUser(context.Background(), user1)
		assert.Nil(err)
		assert.Equal(user1, user.UserID)
		assert.EqualValues(roleListToMap([]string{roles[1], roles[2]}), roleListToMap(user.Roles))
		assert.EqualValues(
			roleListToMap([]string{permissions[1], permissions[2]}),
			roleListToMap(user.AssociatedPermission),
		)
	}

	// Case 5: add user
	user5 := uuid.New().String()
	{
		param := models.UserConfig{UserID: user5}
		assert.Nil(uut.DefineUser(context.Background(), param, []string{roles[1]}))
	}
	{
		_, users, err := uut.GetRoleWithLinkedUsers(context.Background(), roles[0])
		assert.Nil(err)
		assert.Empty(users)
		_, users, err = uut.GetRoleWithLinkedUsers(context.Background(), roles[1])
		assert.Nil(err)
		assert.Len(users, 2)
		uids := []string{}
		for _, userInfo := range users {
			uids = append(uids, userInfo.UserID)
		}
		assert.EqualValues(roleListToMap([]string{user1, user5}), roleListToMap(uids))
		_, users, err = uut.GetRoleWithLinkedUsers(context.Background(), roles[2])
		assert.Nil(err)
		assert.Len(users, 1)
		assert.Equal(user1, users[0].UserID)
	}

	// Case 6: remove a role
	{
		testRoles := map[string]common.UserRoleConfig{
			roles[0]: {AssignedPermissions: []string{permissions[0]}},
			roles[2]: {AssignedPermissions: []string{permissions[1]}},
		}
		assert.Nil(uut.AlignRolesWithConfig(context.Background(), testRoles))
	}
	{
		user, err := uut.GetUser(context.Background(), user1)
		assert.Nil(err)
		assert.Equal(user1, user.UserID)
		assert.EqualValues(roleListToMap([]string{roles[2]}), roleListToMap(user.Roles))
		assert.EqualValues(
			roleListToMap([]string{permissions[1]}), roleListToMap(user.AssociatedPermission),
		)
	}
	{
		user, err := uut.GetUser(context.Background(), user5)
		assert.Nil(err)
		assert.Equal(user5, user.UserID)
		assert.Empty(user.Roles)
		assert.Empty(user.AssociatedPermission)
	}

	// Case 7: set the roles of a user
	{
		testRoles := map[string]common.UserRoleConfig{
			roles[0]: {AssignedPermissions: []string{permissions[0]}},
			roles[2]: {AssignedPermissions: []string{permissions[1]}},
			roles[3]: {AssignedPermissions: []string{permissions[2]}},
		}
		assert.Nil(uut.AlignRolesWithConfig(context.Background(), testRoles))
	}
	{
		newRoles := []string{roles[0], roles[3]}
		assert.Nil(uut.SetUserRoles(context.Background(), user5, newRoles))
	}
	{
		user, err := uut.GetUser(context.Background(), user5)
		assert.Nil(err)
		assert.Equal(user5, user.UserID)
		assert.EqualValues(roleListToMap([]string{roles[0], roles[3]}), roleListToMap(user.Roles))
		assert.EqualValues(
			roleListToMap([]string{permissions[0], permissions[2]}),
			roleListToMap(user.AssociatedPermission),
		)
	}
}

func TestUserPermissionChecking(assignedPermissions *testing.T) {
	assert := assert.New(assignedPermissions)
	log.SetLevel(log.DebugLevel)

	dbName := fmt.Sprintf("/tmp/models_test_%s.db", uuid.New().String())
	log.Debugf("Unit-test DB %s", dbName)
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	assert.Nil(err)
	supportMatch, err := common.GetCustomFieldValidator(
		`^[a-zA-Z0-9-]+$`, `^[a-zA-Z0-9-]+$`, `^[a-zA-Z0-9-]+$`, `^[a-zA-Z0-9-]+$`, `^.+$`,
	)
	assert.Nil(err)
	dbClient, err := models.CreateManagementDBClient(db, supportMatch)
	assert.Nil(err)
	assert.Nil(dbClient.Ready())

	uut, err := CreateManagement(dbClient)
	assert.Nil(err)
	assert.Nil(uut.Ready())

	roles := make([]string, 5)
	for itr := 0; itr < 5; itr++ {
		roles[itr] = uuid.New().String()
	}

	permissions := make([]string, 8)
	for itr := 0; itr < 8; itr++ {
		permissions[itr] = uuid.New().String()
	}

	testRoles := map[string]common.UserRoleConfig{
		roles[0]: {AssignedPermissions: []string{permissions[0], permissions[1], permissions[2]}},
		roles[1]: {AssignedPermissions: []string{permissions[2], permissions[3]}},
		roles[2]: {AssignedPermissions: []string{permissions[1], permissions[4], permissions[5]}},
		roles[3]: {AssignedPermissions: []string{permissions[0], permissions[6]}},
		roles[4]: {AssignedPermissions: []string{permissions[7]}},
	}
	assert.Nil(uut.AlignRolesWithConfig(context.Background(), testRoles))

	userID := uuid.New().String()
	{
		param := models.UserConfig{UserID: userID}
		assert.Nil(uut.DefineUser(context.Background(), param, []string{}))
	}

	getPermissionsOfRoles := func(
		associatedRoles map[string]common.UserRoleConfig, missingRoles map[string]bool,
	) ([]string, []string) {
		associatedPermissions := map[string]bool{}
		for aRole := range associatedRoles {
			for _, permission := range testRoles[aRole].AssignedPermissions {
				associatedPermissions[permission] = true
			}
		}
		notAssociatedPermissions := map[string]bool{}
		for aRole := range missingRoles {
			for _, permission := range testRoles[aRole].AssignedPermissions {
				if _, ok := associatedPermissions[permission]; !ok {
					notAssociatedPermissions[permission] = true
				}
			}
		}
		assignedPermissions := make([]string, 0, len(associatedPermissions))
		for permission := range associatedPermissions {
			assignedPermissions = append(assignedPermissions, permission)
		}
		missingPermissions := make([]string, 0, len(notAssociatedPermissions))
		for permission := range notAssociatedPermissions {
			missingPermissions = append(missingPermissions, permission)
		}
		return assignedPermissions, missingPermissions
	}

	type testCase struct {
		roles map[string]common.UserRoleConfig
	}

	// Case 0: test changes to user assigned roles
	{
		tests := []testCase{
			{roles: map[string]common.UserRoleConfig{
				roles[0]: testRoles[roles[0]],
			}},
			{roles: map[string]common.UserRoleConfig{
				roles[1]: testRoles[roles[1]],
			}},
			{roles: map[string]common.UserRoleConfig{
				roles[0]: testRoles[roles[0]], roles[3]: testRoles[roles[3]],
			}},
			{roles: map[string]common.UserRoleConfig{
				roles[4]: testRoles[roles[4]], roles[2]: testRoles[roles[2]],
			}},
			{roles: map[string]common.UserRoleConfig{
				roles[3]: testRoles[roles[3]],
			}},
			{roles: map[string]common.UserRoleConfig{
				roles[2]: testRoles[roles[2]], roles[4]: testRoles[roles[4]],
			}},
		}

		for _, oneTest := range tests {
			missingRoles := map[string]bool{}
			for _, aRole := range roles {
				if _, ok := oneTest.roles[aRole]; !ok {
					missingRoles[aRole] = true
				}
			}
			newRoles := make([]string, 0, len(oneTest.roles))
			for aRole := range oneTest.roles {
				newRoles = append(newRoles, aRole)
			}
			assigned, missing := getPermissionsOfRoles(oneTest.roles, missingRoles)
			assert.Nil(uut.SetUserRoles(context.Background(), userID, newRoles))
			// Test permission which should be there
			for _, permission := range assigned {
				havePermission, err := uut.DoesUserHavePermission(
					context.Background(), userID, []string{permission},
				)
				assert.Nil(err)
				assert.True(havePermission)
			}
			// Test permission which should be missing
			for _, permission := range missing {
				havePermission, err := uut.DoesUserHavePermission(
					context.Background(), userID, []string{permission},
				)
				assert.Nil(err)
				assert.False(havePermission)
			}
		}
	}

	// Case 1: test changes roles available in instance
	{
		tests := []testCase{
			{roles: map[string]common.UserRoleConfig{
				roles[0]: testRoles[roles[0]],
			}},
			{roles: map[string]common.UserRoleConfig{
				roles[1]: testRoles[roles[1]],
			}},
			{roles: map[string]common.UserRoleConfig{
				roles[0]: testRoles[roles[0]], roles[3]: testRoles[roles[3]],
			}},
			{roles: map[string]common.UserRoleConfig{
				roles[4]: testRoles[roles[4]], roles[2]: testRoles[roles[2]],
			}},
			{roles: map[string]common.UserRoleConfig{
				roles[3]: testRoles[roles[3]],
			}},
			{roles: map[string]common.UserRoleConfig{
				roles[2]: testRoles[roles[2]], roles[4]: testRoles[roles[4]],
			}},
		}

		for idx, oneTest := range tests {
			// Start at initial set of roles
			assert.Nil(uut.AlignRolesWithConfig(context.Background(), testRoles))
			// Give user all roles
			assert.Nil(uut.SetUserRoles(context.Background(), userID, roles))
			// Change the roles available in the system
			assert.Nil(uut.AlignRolesWithConfig(context.Background(), oneTest.roles))

			missingRoles := map[string]bool{}
			for _, aRole := range roles {
				if _, ok := oneTest.roles[aRole]; !ok {
					missingRoles[aRole] = true
				}
			}
			assigned, missing := getPermissionsOfRoles(oneTest.roles, missingRoles)
			// Test permission which should be there
			for _, permission := range assigned {
				havePermission, err := uut.DoesUserHavePermission(
					context.Background(), userID, []string{permission},
				)
				assert.Nil(err)
				assert.Truef(havePermission, "%d", idx)
			}
			// Test permission which should be missing
			for _, permission := range missing {
				havePermission, err := uut.DoesUserHavePermission(
					context.Background(), userID, []string{permission},
				)
				assert.Nil(err)
				assert.Falsef(havePermission, "%d", idx)
			}
		}
	}
}

func roleListToMap(i []string) map[string]bool {
	result := map[string]bool{}
	for _, e := range i {
		result[e] = true
	}
	return result
}
