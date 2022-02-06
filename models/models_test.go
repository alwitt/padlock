package models

import (
	"context"
	"fmt"
	"testing"

	"github.com/alwitt/padlock/common"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestRoleManagement(t *testing.T) {
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
	uut, err := CreateManagementDBClient(db, supportMatch)
	assert.Nil(err)
	assert.Nil(uut.Ready())

	// Case 0: no roles yet
	{
		roles, err := uut.ListAllRoles(context.Background())
		assert.Nil(err)
		assert.Empty(roles)
	}
	{
		users, err := uut.GetUsersOfRole(context.Background(), uuid.New().String())
		assert.NotNil(err)
		assert.Empty(users)
	}

	roles := []string{uuid.New().String(), uuid.New().String(), uuid.New().String()}

	type testCase struct {
		expectedRoles []string
	}
	tests := []testCase{
		{expectedRoles: []string{roles[0]}},
		{expectedRoles: []string{roles[0], roles[2]}},
		{expectedRoles: []string{roles[1], roles[2]}},
	}
	// Case 1: sync DB roles with config
	for idx, oneTest := range tests {
		assert.Nil(uut.AlignRolesWithConfig(context.Background(), oneTest.expectedRoles))
		readRoles, err := uut.ListAllRoles(context.Background())
		assert.Nil(err)
		assert.EqualValuesf(
			roleListToMap(oneTest.expectedRoles), roleListToMap(readRoles), "Case %d", idx,
		)
	}
}

func TestUserManagement(t *testing.T) {
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
	uut, err := CreateManagementDBClient(db, supportMatch)
	assert.Nil(err)
	assert.Nil(uut.Ready())

	// Case 0: no users
	{
		users, err := uut.ListAllUsers(context.Background())
		assert.Nil(err)
		assert.Empty(users)
		_, err = uut.GetUser(context.Background(), uuid.New().String())
		assert.NotNil(err)
		assert.NotNil(uut.DeleteUser(context.Background(), uuid.New().String()))
	}

	roles := []string{uuid.New().String(), uuid.New().String(), uuid.New().String()}

	// Case 1: add user
	user1 := uuid.New().String()
	{
		param := UserConfig{UserID: user1}
		assert.Nil(uut.DefineUser(context.Background(), param, []string{}))
	}
	{
		user, err := uut.GetUser(context.Background(), user1)
		assert.Nil(err)
		assert.Equal(user1, user.UserID)
		assert.Empty(user.Roles)
	}

	// Case 2: add roles to user
	{
		newRoles := []string{roles[0]}
		assert.Nil(uut.AddRolesToUser(context.Background(), user1, newRoles))
		user, err := uut.GetUser(context.Background(), user1)
		assert.Nil(err)
		assert.Equal(user1, user.UserID)
		assert.EqualValues(roleListToMap(newRoles), roleListToMap(user.Roles))
	}

	// Case 3: add more roles to user
	{
		newRoles := []string{roles[0], roles[1]}
		assert.Nil(uut.AddRolesToUser(context.Background(), user1, newRoles))
		user, err := uut.GetUser(context.Background(), user1)
		assert.Nil(err)
		assert.Equal(user1, user.UserID)
		assert.EqualValues(roleListToMap(newRoles), roleListToMap(user.Roles))
	}

	// Case 4: remove roles from user
	{
		removeRoles := []string{roles[0], roles[2]}
		assert.Nil(uut.RemoveRolesFromUser(context.Background(), user1, removeRoles))
		user, err := uut.GetUser(context.Background(), user1)
		assert.Nil(err)
		assert.Equal(user1, user.UserID)
		assert.EqualValues(roleListToMap([]string{roles[1]}), roleListToMap(user.Roles))
	}

	// Case 5: create new user with roles
	user5 := uuid.New().String()
	{
		param := UserConfig{UserID: user5}
		assert.Nil(uut.DefineUser(context.Background(), param, []string{roles[0], roles[2]}))
	}
	{
		user, err := uut.GetUser(context.Background(), user5)
		assert.Nil(err)
		assert.Equal(user5, user.UserID)
		assert.EqualValues(roleListToMap([]string{roles[0], roles[2]}), roleListToMap(user.Roles))
	}

	// Case 6: change user information
	{
		newEmail := "unit-test@testing.org"
		param := UserConfig{UserID: user5, Email: &newEmail}
		assert.Nil(uut.UpdateUser(context.Background(), user5, param))
		user, err := uut.GetUser(context.Background(), user5)
		assert.Nil(err)
		assert.Equal(user5, user.UserID)
		assert.Equal(newEmail, *user.Email)
	}

	// Case 7: delete user
	assert.Nil(uut.DeleteUser(context.Background(), user1))
	{
		_, err := uut.GetUser(context.Background(), user1)
		assert.NotNil(err)
		users, err := uut.GetUsersOfRole(context.Background(), roles[1])
		assert.Nil(err)
		assert.Empty(users)
		users, err = uut.GetUsersOfRole(context.Background(), roles[0])
		assert.Nil(err)
		assert.Len(users, 1)
		assert.Equal(user5, users[0].UserID)
		users, err = uut.GetUsersOfRole(context.Background(), roles[2])
		assert.Nil(err)
		assert.Len(users, 1)
		assert.Equal(user5, users[0].UserID)
	}
}

func TestUserAndRoleManagement(t *testing.T) {
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
	uut, err := CreateManagementDBClient(db, supportMatch)
	assert.Nil(err)
	assert.Nil(uut.Ready())

	roles := []string{uuid.New().String(), uuid.New().String(), uuid.New().String()}

	// Case 1: add user
	user1 := uuid.New().String()
	{
		param := UserConfig{UserID: user1}
		assert.Nil(uut.DefineUser(context.Background(), param, []string{roles[0], roles[1]}))
	}
	{
		user, err := uut.GetUser(context.Background(), user1)
		assert.Nil(err)
		assert.Equal(user1, user.UserID)
		assert.EqualValues(roleListToMap([]string{roles[0], roles[1]}), roleListToMap(user.Roles))
	}

	// Case 2: add user
	user2 := uuid.New().String()
	{
		param := UserConfig{UserID: user2}
		assert.Nil(uut.DefineUser(context.Background(), param, []string{roles[0], roles[2]}))
	}
	{
		user, err := uut.GetUser(context.Background(), user2)
		assert.Nil(err)
		assert.Equal(user2, user.UserID)
		assert.EqualValues(roleListToMap([]string{roles[0], roles[2]}), roleListToMap(user.Roles))
	}

	// Case 3: resync roles
	assert.Nil(uut.AlignRolesWithConfig(context.Background(), []string{roles[0]}))
	{
		user, err := uut.GetUser(context.Background(), user1)
		assert.Nil(err)
		assert.Equal(user1, user.UserID)
		assert.EqualValues(roleListToMap([]string{roles[0]}), roleListToMap(user.Roles))
	}
	{
		user, err := uut.GetUser(context.Background(), user2)
		assert.Nil(err)
		assert.Equal(user2, user.UserID)
		assert.EqualValues(roleListToMap([]string{roles[0]}), roleListToMap(user.Roles))
	}
}

func roleListToMap(i []string) map[string]bool {
	result := map[string]bool{}
	for _, e := range i {
		result[e] = true
	}
	return result
}
