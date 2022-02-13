package apis

import (
	"bytes"
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

func TestUserManagementAPI(t *testing.T) {
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

	// Case 1: no users
	{
		rid := uuid.New().String()
		req, err := http.NewRequest("GET", fmt.Sprintf("/v1/user/%s", uuid.New().String()), nil)
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		router := mux.NewRouter()
		respRecorder := httptest.NewRecorder()
		router.HandleFunc("/v1/user/{userID}", uut.LoggingMiddleware(uut.GetUserHandler()))
		router.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusInternalServerError, respRecorder.Code)
		checkHeader(respRecorder, rid)
	}
	{
		rid := uuid.New().String()
		req, err := http.NewRequest("GET", "/v1/user", nil)
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		router := mux.NewRouter()
		respRecorder := httptest.NewRecorder()
		router.HandleFunc("/v1/user", uut.LoggingMiddleware(uut.ListAllUsersHandler()))
		router.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid)

		respMsg := respRecorder.Body.Bytes()
		var msg RespListAllUsers
		assert.Nil(json.Unmarshal(respMsg, &msg))
		assert.True(msg.Success)
		assert.Equal(rid, msg.RequestID)
		assert.Empty(msg.Users)
	}

	// Case 2: create new user
	user2 := uuid.New().String()
	{
		params := ReqNewUserParams{User: models.UserConfig{UserID: user2}}
		t, err := json.Marshal(&params)
		assert.Nil(err)
		rid := uuid.New().String()
		req, err := http.NewRequest("POST", "/v1/user", bytes.NewReader(t))
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		router := mux.NewRouter()
		respRecorder := httptest.NewRecorder()
		router.HandleFunc("/v1/user", uut.LoggingMiddleware(uut.DefineUserHandler()))
		router.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid)
	}
	{
		rid := uuid.New().String()
		req, err := http.NewRequest("GET", fmt.Sprintf("/v1/user/%s", user2), nil)
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		router := mux.NewRouter()
		respRecorder := httptest.NewRecorder()
		router.HandleFunc("/v1/user/{userID}", uut.LoggingMiddleware(uut.GetUserHandler()))
		router.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid)

		respMsg := respRecorder.Body.Bytes()
		var msg RespUserInfo
		assert.Nil(json.Unmarshal(respMsg, &msg))
		assert.True(msg.Success)
		assert.Equal(rid, msg.RequestID)
		assert.Equal(user2, msg.User.UserID)
		assert.Empty(msg.User.Roles)
		assert.Empty(msg.User.AssociatedPermission)
	}

	strListToMap := func(orig []string) map[string]bool {
		result := map[string]bool{}
		for _, v := range orig {
			result[v] = true
		}
		return result
	}

	// Case 3: add roles to user
	{
		params := ReqNewUserRoles{Roles: []string{roles[0], roles[2]}}
		t, err := json.Marshal(&params)
		assert.Nil(err)
		rid := uuid.New().String()
		req, err := http.NewRequest("PUT", fmt.Sprintf("/v1/user/%s/roles", user2), bytes.NewReader(t))
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		router := mux.NewRouter()
		respRecorder := httptest.NewRecorder()
		router.HandleFunc(
			"/v1/user/{userID}/roles", uut.LoggingMiddleware(uut.UpdateUserRolesHandler()),
		)
		router.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid)
	}
	{
		rid := uuid.New().String()
		req, err := http.NewRequest("GET", fmt.Sprintf("/v1/user/%s", user2), nil)
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		router := mux.NewRouter()
		respRecorder := httptest.NewRecorder()
		router.HandleFunc("/v1/user/{userID}", uut.LoggingMiddleware(uut.GetUserHandler()))
		router.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid)

		respMsg := respRecorder.Body.Bytes()
		var msg RespUserInfo
		assert.Nil(json.Unmarshal(respMsg, &msg))
		assert.EqualValues(strListToMap([]string{roles[0], roles[2]}), strListToMap(msg.User.Roles))
		assert.EqualValues(
			strListToMap(
				append(
					testRoles[roles[0]].AssignedPermissions,
					testRoles[roles[2]].AssignedPermissions...,
				),
			),
			strListToMap(msg.User.AssociatedPermission),
		)
	}

	// Case 4: change user information
	{
		params := models.UserConfig{UserID: user2, Username: &user2}
		t, err := json.Marshal(&params)
		assert.Nil(err)
		rid := uuid.New().String()
		req, err := http.NewRequest("PUT", fmt.Sprintf("/v1/user/%s", user2), bytes.NewReader(t))
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		router := mux.NewRouter()
		respRecorder := httptest.NewRecorder()
		router.HandleFunc("/v1/user/{userID}", uut.LoggingMiddleware(uut.UpdateUserHandler()))
		router.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid)
	}
	{
		rid := uuid.New().String()
		req, err := http.NewRequest("GET", fmt.Sprintf("/v1/user/%s", user2), nil)
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		router := mux.NewRouter()
		respRecorder := httptest.NewRecorder()
		router.HandleFunc("/v1/user/{userID}", uut.LoggingMiddleware(uut.GetUserHandler()))
		router.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid)

		respMsg := respRecorder.Body.Bytes()
		var msg RespUserInfo
		assert.Nil(json.Unmarshal(respMsg, &msg))
		assert.Equal(user2, *msg.User.Username)
	}

	// Case 5: delete user
	{
		rid := uuid.New().String()
		req, err := http.NewRequest("DELETE", fmt.Sprintf("/v1/user/%s", user2), nil)
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		router := mux.NewRouter()
		respRecorder := httptest.NewRecorder()
		router.HandleFunc("/v1/user/{userID}", uut.LoggingMiddleware(uut.DeleteUserHandler()))
		router.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid)
	}
	{
		rid := uuid.New().String()
		req, err := http.NewRequest("GET", fmt.Sprintf("/v1/user/%s", user2), nil)
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		router := mux.NewRouter()
		respRecorder := httptest.NewRecorder()
		router.HandleFunc("/v1/user/{userID}", uut.LoggingMiddleware(uut.GetUserHandler()))
		router.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusInternalServerError, respRecorder.Code)
		checkHeader(respRecorder, rid)
	}

	// Case 6: create user with roles
	user6 := uuid.New().String()
	{
		params := ReqNewUserParams{
			User: models.UserConfig{UserID: user6}, Roles: []string{roles[1], roles[2]},
		}
		t, err := json.Marshal(&params)
		assert.Nil(err)
		rid := uuid.New().String()
		req, err := http.NewRequest("POST", "/v1/user", bytes.NewReader(t))
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		router := mux.NewRouter()
		respRecorder := httptest.NewRecorder()
		router.HandleFunc("/v1/user", uut.LoggingMiddleware(uut.DefineUserHandler()))
		router.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid)
	}
	{
		rid := uuid.New().String()
		req, err := http.NewRequest("GET", fmt.Sprintf("/v1/user/%s", user6), nil)
		assert.Nil(err)
		req.Header.Add("Padlock-Request-ID", rid)

		router := mux.NewRouter()
		respRecorder := httptest.NewRecorder()
		router.HandleFunc("/v1/user/{userID}", uut.LoggingMiddleware(uut.GetUserHandler()))
		router.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid)

		respMsg := respRecorder.Body.Bytes()
		var msg RespUserInfo
		assert.Nil(json.Unmarshal(respMsg, &msg))
		assert.EqualValues(strListToMap([]string{roles[1], roles[2]}), strListToMap(msg.User.Roles))
		assert.EqualValues(
			strListToMap(
				append(
					testRoles[roles[1]].AssignedPermissions,
					testRoles[roles[2]].AssignedPermissions...,
				),
			),
			strListToMap(msg.User.AssociatedPermission),
		)
	}
}
