package apis

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/match"
	"github.com/alwitt/padlock/models"
	"github.com/alwitt/padlock/users"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestAuthorization(t *testing.T) {
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

	// Define test roles
	roles := make([]string, 4)
	for itr := 0; itr < 4; itr++ {
		roles[itr] = uuid.New().String()
	}
	permissions := make([]string, 4)
	for itr := 0; itr < 4; itr++ {
		permissions[itr] = uuid.New().String()
	}
	testRoles := map[string]common.UserRoleConfig{
		roles[0]: {AssignedPermissions: []string{permissions[0], permissions[1]}},
		roles[1]: {AssignedPermissions: []string{permissions[2]}},
		roles[2]: {AssignedPermissions: []string{permissions[1], permissions[2]}},
		roles[3]: {AssignedPermissions: []string{permissions[3]}},
	}
	assert.Nil(mgmtCore.AlignRolesWithConfig(context.Background(), testRoles))

	// Define authorization match rules
	testHost0 := fmt.Sprintf("%s.unit-test.org", uuid.New().String())
	testHost1 := fmt.Sprintf("%s.unit-test.org", uuid.New().String())
	matchRules := match.TargetGroupSpec{
		AllowedHosts: map[string]match.TargetHostSpec{
			testHost0: {
				TargetHost: testHost0,
				AllowedPathsForHost: []match.TargetPathSpec{
					{
						PathPattern: `^/path1/[a-zA-Z0-9-]+$`,
						PermissionsForMethod: map[string][]string{
							"GET": {permissions[0], permissions[1]},
							"PUT": {permissions[1]},
						},
					},
				},
			},
			testHost1: {
				TargetHost: testHost1,
				AllowedPathsForHost: []match.TargetPathSpec{
					{
						PathPattern: `^/path2/[[:alnum:]]+$`,
						PermissionsForMethod: map[string][]string{
							"GET": {permissions[2]},
							"PUT": {permissions[2]},
						},
					},
					{
						PathPattern: `^/path2$`,
						PermissionsForMethod: map[string][]string{
							"GET":  {permissions[0], permissions[2]},
							"POST": {permissions[0]},
						},
					},
				},
			},
			"*": {
				TargetHost: testHost1,
				AllowedPathsForHost: []match.TargetPathSpec{
					{
						PathPattern: `^.+$`,
						PermissionsForMethod: map[string][]string{
							"*": {permissions[3]},
						},
					},
				},
			},
		},
	}
	restRequestMatcher, err := match.DefineTargetGroupMatcher(matchRules)
	assert.Nil(err)

	authRequestParamLoc := common.AuthorizeRequestParamLocConfig{
		Host:      "X-Forwarded-Host",
		Path:      "X-Forwarded-Uri",
		Method:    "X-Forwarded-Method",
		UserID:    "X-Caller-UserID",
		Username:  "X-Caller-Username",
		FirstName: "X-Caller-Firstname",
		LastName:  "X-Caller-Lastname",
		Email:     "X-Caller-Email",
	}

	requestIDHeader := "Padlock-Unit-Tester"

	checkHeader := func(w http.ResponseWriter, reqID string, stackOffset int) {
		_, _, ln, ok := runtime.Caller(2)
		assert.True(ok)
		assert.Equalf(reqID, w.Header().Get(requestIDHeader), "Called@%d", ln)
		assert.Equalf("application/json", w.Header().Get("content-type"), "Called@%d", ln)
	}

	// --------------------------------------------------------------------------
	// First test without auto add

	uut, err := defineAuthorizationHandler(
		common.HTTPRequestLogging{DoNotLogHeaders: []string{}, RequestIDHeader: requestIDHeader},
		mgmtCore,
		restRequestMatcher,
		supportMatch,
		authRequestParamLoc,
		common.UnknownUserActionConfig{AutoAdd: false},
		nil,
	)
	assert.Nil(err)
	livness := defineAuthorizationLivenessHandler(
		common.HTTPRequestLogging{DoNotLogHeaders: []string{}, RequestIDHeader: requestIDHeader},
		mgmtCore,
	)

	// Case 0: verify ready
	{
		rid := uuid.New().String()
		req, err := http.NewRequest("GET", "/v1/ready", nil)
		assert.Nil(err)
		req.Header.Add(requestIDHeader, rid)

		respRecorder := httptest.NewRecorder()
		handler := livness.LoggingMiddleware(livness.ReadyHandler())
		handler.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid, 1)
	}

	type testCase struct {
		host, path, method, userID           string
		userName, firstName, lastName, email *string
		status                               int
	}
	executeTest := func(tc testCase) {
		_, _, ln, ok := runtime.Caller(1)
		assert.True(ok)

		rid := uuid.New().String()
		req, err := http.NewRequest("GET", "/v1/allow", nil)
		assert.Nilf(err, "Called@%d", ln)
		req.Header.Add(requestIDHeader, rid)

		// Add parameter for request to authorize
		req.Header.Add(authRequestParamLoc.Host, tc.host)
		req.Header.Add(authRequestParamLoc.Path, tc.path)
		req.Header.Add(authRequestParamLoc.Method, tc.method)
		req.Header.Add(authRequestParamLoc.UserID, tc.userID)
		if tc.userName != nil {
			req.Header.Add(authRequestParamLoc.Username, *tc.userName)
		}
		if tc.firstName != nil {
			req.Header.Add(authRequestParamLoc.FirstName, *tc.firstName)
		}
		if tc.lastName != nil {
			req.Header.Add(authRequestParamLoc.LastName, *tc.lastName)
		}
		if tc.email != nil {
			req.Header.Add(authRequestParamLoc.Email, *tc.email)
		}

		respRecorder := httptest.NewRecorder()
		handler := uut.LoggingMiddleware(uut.ParamReadMiddleware(uut.AllowHandler()))
		handler.ServeHTTP(respRecorder, req)

		assert.Equalf(tc.status, respRecorder.Code, "Called@%d", ln)
		checkHeader(respRecorder, rid, 2)
	}

	// Case 1: check with unknown user
	{
		checkParam := testCase{
			host: testHost0, path: "/path2", method: "POST", userID: uuid.New().String(),
		}
		checkParam.status = http.StatusForbidden
		executeTest(checkParam)
	}

	// Case 2: define user for testing
	user2 := uuid.New().String()
	{
		params := models.UserConfig{UserID: user2}
		assert.Nil(mgmtCore.DefineUser(context.Background(), params, nil))
	}
	// Check with user
	{
		checkParam := testCase{
			host: testHost1, path: "/path2", method: "POST", userID: user2,
		}
		checkParam.status = http.StatusForbidden
		executeTest(checkParam)
	}

	// Case 3: change user permissions
	assert.Nil(mgmtCore.SetUserRoles(context.Background(), user2, []string{roles[0]}))
	// Check with user
	{
		checkParam := testCase{
			host: testHost1, path: "/path2", method: "POST", userID: user2,
		}
		checkParam.status = http.StatusOK
		executeTest(checkParam)
	}
	{
		checkParam := testCase{
			host: testHost1, path: "/path2/mkas2df3u13nor", method: "GET", userID: user2,
		}
		checkParam.status = http.StatusForbidden
		executeTest(checkParam)
	}

	// Case 4: change user permissions
	assert.Nil(mgmtCore.SetUserRoles(context.Background(), user2, []string{roles[2]}))
	{
		checkParam := testCase{
			host: testHost1, path: "/path2/mkas2df3u13nor", method: "GET", userID: user2,
		}
		checkParam.status = http.StatusOK
		executeTest(checkParam)
	}
	{
		checkParam := testCase{
			host:   testHost0,
			path:   fmt.Sprintf("/path1/%s", uuid.New().String()),
			method: "PUT",
			userID: user2,
			status: http.StatusOK,
		}
		executeTest(checkParam)
	}

	// --------------------------------------------------------------------------
	// Then test with auto add

	uut, err = defineAuthorizationHandler(
		common.HTTPRequestLogging{DoNotLogHeaders: []string{}, RequestIDHeader: requestIDHeader},
		mgmtCore,
		restRequestMatcher,
		supportMatch,
		authRequestParamLoc,
		common.UnknownUserActionConfig{AutoAdd: true},
		nil,
	)
	assert.Nil(err)

	// Case 5: verify ready
	{
		rid := uuid.New().String()
		req, err := http.NewRequest("GET", "/v1/ready", nil)
		assert.Nil(err)
		req.Header.Add(requestIDHeader, rid)

		respRecorder := httptest.NewRecorder()
		handler := livness.LoggingMiddleware(livness.ReadyHandler())
		handler.ServeHTTP(respRecorder, req)

		assert.Equal(http.StatusOK, respRecorder.Code)
		checkHeader(respRecorder, rid, 1)
	}

	// Case 6: check authorization with a new user
	user6 := uuid.New().String()
	{
		checkParam := testCase{
			host: testHost1, path: "/path2", method: "POST", userID: user6,
		}
		checkParam.status = http.StatusForbidden
		executeTest(checkParam)
	}

	// Case 7: give new user permissions
	assert.Nil(mgmtCore.SetUserRoles(context.Background(), user6, []string{roles[3]}))
	{
		checkParam := testCase{
			host:   fmt.Sprintf("%s.unittest.com", uuid.New().String()),
			path:   "/path4",
			method: "POST",
			userID: user6,
			status: http.StatusOK,
		}
		executeTest(checkParam)
	}
}
