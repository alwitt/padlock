package models

import (
	"context"
	"fmt"
	"testing"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
)

func TestRoleManagement(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	dbName := fmt.Sprintf("/tmp/models_test_%s.db", uuid.New().String())
	log.Debugf("Unit-test DB %s", dbName)
	uut, err := CreateManagementDBClient(sqlite.Open(dbName))
	assert.Nil(err)
	assert.Nil(uut.Ready())

	// Case 0: no roles yet
	{
		roles, err := uut.ListAllRoles(context.Background())
		assert.Nil(err)
		assert.Len(roles, 0)
	}
	{
		users, err := uut.GetUsersOfRole(context.Background(), uuid.New().String())
		assert.NotNil(err)
		assert.Len(users, 0)
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
		expected := map[string]bool{}
		for _, e := range oneTest.expectedRoles {
			expected[e] = true
		}
		gotten := map[string]bool{}
		for _, g := range readRoles {
			gotten[g] = true
		}
		assert.EqualValuesf(expected, gotten, "Case %d", idx)
	}
}
