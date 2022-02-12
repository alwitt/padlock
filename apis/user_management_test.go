package apis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/models"
	"github.com/alwitt/padlock/users"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestRoleManagementAPI(t *testing.T) {
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

	mgmtCore, err := users.CreateManagement(dbClient)
	assert.Nil(err)
	assert.Nil(mgmtCore.Ready())

	uut, err := defineUserManagementHandler(
		common.HTTPRequestLogging{DoNotLogHeaders: []string{}}, mgmtCore, supportMatch,
	)
	assert.Nil(err)

	checkHeader := func(w http.ResponseWriter, reqID string) {
		assert.Equal(reqID, w.Header().Get("Padlock-Request-ID"))
		assert.Equal("application/json", w.Header().Get("content-type"))
	}

	// Case 0: check ready
	{
		rid := uuid.New().String()
		req, err := http.NewRequest("GET", "/v1/ready", nil)
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		respRecorder := httptest.NewRecorder()
		handler := uut.LoggingMiddleware(uut.ReadyHandler())
		handler.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid)
	}

	// Case 1: no roles
	{
		rid := uuid.New().String()
		req, err := http.NewRequest("GET", fmt.Sprintf("/v1/role/%s", uuid.New().String()), nil)
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		router := mux.NewRouter()
		respRecorder := httptest.NewRecorder()
		router.HandleFunc("/v1/role/{roleName}", uut.LoggingMiddleware(uut.GetRoleHandler()))
		router.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusInternalServerError, respRecorder.Code)
		checkHeader(respRecorder, rid)
	}

	// Define test roles
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
	assert.Nil(mgmtCore.AlignRolesWithConfig(context.Background(), testRoles))

	// Case 2: check all the roles
	{
		rid := uuid.New().String()
		req, err := http.NewRequest("GET", "/v1/role", nil)
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		respRecorder := httptest.NewRecorder()
		handler := uut.LoggingMiddleware(uut.ListAllRolesHandler())
		handler.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid)

		respMsg := respRecorder.Body.Bytes()
		var msg RespListAllRoles
		assert.Nil(json.Unmarshal(respMsg, &msg))
		assert.True(msg.Success)
		assert.Equal(rid, msg.RequestID)
		assert.Len(msg.Roles, len(testRoles))
		for roleName, roleInfo := range testRoles {
			readInfo, ok := msg.Roles[roleName]
			assert.True(ok)
			assert.EqualValues(roleInfo, readInfo)
		}
	}
	{
		rid := uuid.New().String()
		req, err := http.NewRequest("GET", fmt.Sprintf("/v1/role/%s", roles[2]), nil)
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		router := mux.NewRouter()
		respRecorder := httptest.NewRecorder()
		router.HandleFunc("/v1/role/{roleName}", uut.LoggingMiddleware(uut.GetRoleHandler()))
		router.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid)

		respMsg := respRecorder.Body.Bytes()
		var msg RespRoleInfo
		assert.Nil(json.Unmarshal(respMsg, &msg))
		assert.True(msg.Success)
		assert.Equal(rid, msg.RequestID)
		assert.EqualValues(testRoles[roles[2]], msg.Role)
		assert.Empty(msg.AssignedUsers)
	}
}
