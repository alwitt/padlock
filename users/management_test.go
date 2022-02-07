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
}
