package match

import (
	"context"
	"fmt"
	"testing"

	"github.com/alwitt/padlock/user"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestTargetHostMatcher(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	type testCase struct {
		request             RequestParam
		expectedErr         bool
		expectedPermissions []user.Permission
	}

	// Case 0: test URI pattern length sorting
	{
		spec := TargetHostSpec{
			TargetHost: "unit-test",
			AllowedURIsForHost: []TargetURISpec{
				{
					Pattern: `^/path1/very/very/very/long$`,
					PermissionsForMethod: map[string][]user.Permission{
						"GET":  {"spec0.0", "spec0.1"},
						"POST": {"spec0.2"},
					},
				},
				{
					Pattern: `^/path1/short$`,
					PermissionsForMethod: map[string][]user.Permission{
						"GET":  {"spec0.0", "spec0.1"},
						"POST": {"spec0.2"},
					},
				},
				{
					Pattern: `^/shortest$`,
					PermissionsForMethod: map[string][]user.Permission{
						"GET":  {"spec0.0", "spec0.1"},
						"POST": {"spec0.2"},
					},
				},
				{
					Pattern: `^/path1/very/very/long$`,
					PermissionsForMethod: map[string][]user.Permission{
						"GET":  {"spec0.0", "spec0.1"},
						"POST": {"spec0.2"},
					},
				},
				{
					Pattern: `^/path1/very/long$`,
					PermissionsForMethod: map[string][]user.Permission{
						"GET":  {"spec0.0", "spec0.1"},
						"POST": {"spec0.2"},
					},
				},
			},
		}
		expectedOrder := []string{
			`^/path1/very/very/very/long$`,
			`^/path1/very/very/long$`,
			`^/path1/very/long$`,
			`^/path1/short$`,
			`^/shortest$`,
		}
		uut, err := defineTargetHostMatcher(spec)
		assert.Nil(err)
		uriMatchers := uut.uriMatchers
		assert.Equal(len(expectedOrder), len(uriMatchers))
		for idx, matcher := range uriMatchers {
			assert.Equal(expectedOrder[idx], matcher.Pattern)
		}
	}

	// Case 1: test URI selection
	{
		spec := TargetHostSpec{
			TargetHost: "unit-test",
			AllowedURIsForHost: []TargetURISpec{
				{
					Pattern: `^/part1/[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}/part2/[[:alnum:]]+$`,
					PermissionsForMethod: map[string][]user.Permission{
						"GET":  {"spec1.0", "spec1.1"},
						"POST": {"spec1.2"},
					},
				},
				{
					Pattern: `^/part1/[[:alnum:]]+$`,
					PermissionsForMethod: map[string][]user.Permission{
						"GET": {"spec1.3", "spec1.4"},
						"PUT": {"spec1.5"},
					},
				},
				{
					Pattern: `^/part1`,
					PermissionsForMethod: map[string][]user.Permission{
						"*": {"spec1.6"},
					},
				},
				{
					Pattern: `^/part1/[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}`,
					PermissionsForMethod: map[string][]user.Permission{
						"GET": {"spec1.7", "spec1.8"},
						"PUT": {"spec1.9"},
					},
				},
			},
		}
		uut, err := defineTargetHostMatcher(spec)
		assert.Nil(err)

		cases := []testCase{
			{
				request: RequestParam{
					URI:    fmt.Sprintf("/part1/%s/part2/%s", uuid.New().String(), "09ma8aImWm"),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: []user.Permission{"spec1.0", "spec1.1"},
			},
			{
				request: RequestParam{
					URI:    fmt.Sprintf("/part1/%s", "09ma8aImWm"),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: []user.Permission{"spec1.3", "spec1.4"},
			},
			{
				request: RequestParam{
					URI:    fmt.Sprintf("/part1/%s/part2/%s", uuid.New().String(), uuid.New().String()),
					Method: "PUT",
				},
				expectedErr:         false,
				expectedPermissions: []user.Permission{"spec1.9"},
			},
			{
				request: RequestParam{
					URI:    fmt.Sprintf("/part1/%s/part2/%s", uuid.New().String(), uuid.New().String()),
					Method: "DELETE",
				},
				expectedErr:         false,
				expectedPermissions: []user.Permission{"spec1.6"},
			},
			{
				request: RequestParam{
					URI:    fmt.Sprintf("/part1/%s/part2/%s", "8xzvkm4r0j94t2m0", uuid.New().String()),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: []user.Permission{"spec1.6"},
			},
			{
				request: RequestParam{
					URI:    fmt.Sprintf("/part3/%s/part2/%s", "8xzvkm4r0j94t2m0", uuid.New().String()),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: nil,
			},
		}

		for _, oneCase := range cases {
			permissions, err := uut.Match(context.Background(), oneCase.request)
			if oneCase.expectedErr {
				assert.NotNilf(err, oneCase.request.String())
			} else {
				assert.Nilf(err, oneCase.request.String())
			}
			assert.Equalf(oneCase.expectedPermissions, permissions, oneCase.request.String())
		}
	}
}
