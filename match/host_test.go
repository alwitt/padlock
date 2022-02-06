package match

import (
	"context"
	"fmt"
	"testing"

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
		expectedPermissions []string
	}

	// Case 0: test path pattern length sorting
	{
		spec := TargetHostSpec{
			TargetHost: "unit-test",
			AllowedPathsForHost: []TargetPathSpec{
				{
					PathPattern: `^/path1/very/very/very/long$`,
					PermissionsForMethod: map[string][]string{
						"GET":  {"spec0.0", "spec0.1"},
						"POST": {"spec0.2"},
					},
				},
				{
					PathPattern: `^/path1/short$`,
					PermissionsForMethod: map[string][]string{
						"GET":  {"spec0.0", "spec0.1"},
						"POST": {"spec0.2"},
					},
				},
				{
					PathPattern: `^/shortest$`,
					PermissionsForMethod: map[string][]string{
						"GET":  {"spec0.0", "spec0.1"},
						"POST": {"spec0.2"},
					},
				},
				{
					PathPattern: `^/path1/very/very/long$`,
					PermissionsForMethod: map[string][]string{
						"GET":  {"spec0.0", "spec0.1"},
						"POST": {"spec0.2"},
					},
				},
				{
					PathPattern: `^/path1/very/long$`,
					PermissionsForMethod: map[string][]string{
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
		pathMatchers := uut.pathMatchers
		assert.Equal(len(expectedOrder), len(pathMatchers))
		for idx, matcher := range pathMatchers {
			assert.Equal(expectedOrder[idx], matcher.PathPattern)
		}
	}

	// Case 1: test path selection
	{
		spec := TargetHostSpec{
			TargetHost: "unit-test",
			AllowedPathsForHost: []TargetPathSpec{
				{
					PathPattern: `^/part1/[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}/part2/[[:alnum:]]+$`,
					PermissionsForMethod: map[string][]string{
						"GET":  {"spec1.0", "spec1.1"},
						"POST": {"spec1.2"},
					},
				},
				{
					PathPattern: `^/part1/[[:alnum:]]+$`,
					PermissionsForMethod: map[string][]string{
						"GET": {"spec1.3", "spec1.4"},
						"PUT": {"spec1.5"},
					},
				},
				{
					PathPattern: `^/part1`,
					PermissionsForMethod: map[string][]string{
						"*": {"spec1.6"},
					},
				},
				{
					PathPattern: `^/part1/[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}`,
					PermissionsForMethod: map[string][]string{
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
					Path:   fmt.Sprintf("/part1/%s/part2/%s", uuid.New().String(), "09ma8aImWm"),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: []string{"spec1.0", "spec1.1"},
			},
			{
				request: RequestParam{
					Path:   fmt.Sprintf("/part1/%s", "09ma8aImWm"),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: []string{"spec1.3", "spec1.4"},
			},
			{
				request: RequestParam{
					Path:   fmt.Sprintf("/part1/%s/part2/%s", uuid.New().String(), uuid.New().String()),
					Method: "PUT",
				},
				expectedErr:         false,
				expectedPermissions: []string{"spec1.9"},
			},
			{
				request: RequestParam{
					Path:   fmt.Sprintf("/part1/%s/part2/%s", uuid.New().String(), uuid.New().String()),
					Method: "DELETE",
				},
				expectedErr:         false,
				expectedPermissions: []string{"spec1.6"},
			},
			{
				request: RequestParam{
					Path:   fmt.Sprintf("/part1/%s/part2/%s", "8xzvkm4r0j94t2m0", uuid.New().String()),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: []string{"spec1.6"},
			},
			{
				request: RequestParam{
					Path:   fmt.Sprintf("/part3/%s/part2/%s", "8xzvkm4r0j94t2m0", uuid.New().String()),
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
