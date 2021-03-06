package match

import (
	"context"
	"fmt"
	"testing"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestTargetPathMatcher(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	type testCase struct {
		request             RequestParam
		expectedErr         bool
		expectedPermissions []string
	}

	// Case 0: simple case
	{
		spec := TargetPathSpec{
			PathPattern: `^/path$`,
			PermissionsForMethod: map[string][]string{
				"GET":  {"spec0.0", "spec0.1"},
				"POST": {"spec0.2"},
			},
		}
		uut, err := defineTargetPathMatcher("unit-test", spec)
		assert.Nil(err)

		cases := []testCase{
			{
				request:             RequestParam{Path: "/path", Method: "GET"},
				expectedErr:         false,
				expectedPermissions: []string{"spec0.0", "spec0.1"},
			},
			{
				request:             RequestParam{Path: "/path", Method: "DELETE"},
				expectedErr:         false,
				expectedPermissions: nil,
			},
			{
				request:             RequestParam{Path: "/path", Method: "POST"},
				expectedErr:         false,
				expectedPermissions: []string{"spec0.2"},
			},
			{
				request:             RequestParam{Path: "/paths", Method: "POST"},
				expectedErr:         false,
				expectedPermissions: nil,
			},
			{
				request:             RequestParam{Method: "GET"},
				expectedErr:         true,
				expectedPermissions: nil,
			},
			{
				request:             RequestParam{Path: "/path", Method: "FETCH"},
				expectedErr:         true,
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

	// Case 1: wildcard methods
	{
		spec := TargetPathSpec{
			PathPattern: `^/paths$`,
			PermissionsForMethod: map[string][]string{
				"GET": {"spec1.0", "spec1.1"},
				"*":   {"spec1.2"},
			},
		}
		uut, err := defineTargetPathMatcher("unit-test", spec)
		assert.Nil(err)

		cases := []testCase{
			{
				request:             RequestParam{Path: "/paths", Method: "GET"},
				expectedErr:         false,
				expectedPermissions: []string{"spec1.0", "spec1.1"},
			},
			{
				request:             RequestParam{Path: "/paths", Method: "DELETE"},
				expectedErr:         false,
				expectedPermissions: []string{"spec1.2"},
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

	// Case 2: complex path matching
	{
		spec := TargetPathSpec{
			PathPattern: `^/part1/([\w\.]+)/part2/([\w-]+)$`,
			PermissionsForMethod: map[string][]string{
				"GET":    {"spec2.0", "spec2.1"},
				"DELETE": {"spec2.2"},
				"*":      {"spec2.3"},
			},
		}
		uut, err := defineTargetPathMatcher("unit-test", spec)
		assert.Nil(err)

		cases := []testCase{
			{
				request: RequestParam{
					Path:   fmt.Sprintf("/part1/%s/part2/%s", "af8j90a.8mfas", uuid.New().String()),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: []string{"spec2.0", "spec2.1"},
			},
			{
				request: RequestParam{
					Path:   fmt.Sprintf("/part1/%s/part2/%s", uuid.New().String(), uuid.New().String()),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: nil,
			},
			{
				request: RequestParam{
					Path:   fmt.Sprintf("/part1/%s/part2/%s", "09094.a94.mkva", "mna9-439mkas-"),
					Method: "DELETE",
				},
				expectedErr:         false,
				expectedPermissions: []string{"spec2.2"},
			},
			{
				request: RequestParam{
					Path:   fmt.Sprintf("/part1/%s/%s", "af8j90a.8mfas", uuid.New().String()),
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
