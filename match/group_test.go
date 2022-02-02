package match

import (
	"context"
	"fmt"
	"testing"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestTargetGroupMatcher(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	type testCase struct {
		request             RequestParam
		expectedErr         bool
		expectedPermissions []string
	}

	testHost0 := fmt.Sprintf("%s.unit-test.org", uuid.New().String())
	testHost1 := fmt.Sprintf("%s.unit-test.org", uuid.New().String())

	// Case 0: test host selection
	{
		spec := TargetGroupSpec{
			AllowedHosts: map[string]TargetHostSpec{
				testHost0: {
					TargetHost: testHost0,
					AllowedURIsForHost: []TargetURISpec{
						{
							Pattern: `^/part1/[[:alnum:]]+$`,
							PermissionsForMethod: map[string][]string{
								"GET": {"spec0.0", "spec0.1"},
								"PUT": {"spec0.2"},
							},
						},
					},
				},
				testHost1: {
					TargetHost: testHost1,
					AllowedURIsForHost: []TargetURISpec{
						{
							Pattern: `^/part2/[[:alnum:]]+$`,
							PermissionsForMethod: map[string][]string{
								"GET": {"spec0.3", "spec0.4"},
								"PUT": {"spec0.5"},
							},
						},
					},
				},
			},
		}
		uut, err := DefineTargetGroupMatcher(spec)
		assert.Nil(err)

		cases := []testCase{
			{
				request: RequestParam{
					Host:   &testHost0,
					URI:    fmt.Sprintf("/part1/%s", "am9j42qmfas"),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: []string{"spec0.0", "spec0.1"},
			},
			{
				request: RequestParam{
					Host:   &testHost0,
					URI:    fmt.Sprintf("/part2/%s", "103kf9wam3"),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: nil,
			},
			{
				request: RequestParam{
					Host: func() *string {
						t := fmt.Sprintf("%s.unit-test.org", uuid.New().String())
						return &t
					}(),
					URI:    fmt.Sprintf("/part1/%s", "am9j42qmfas"),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: nil,
			},
			{
				request: RequestParam{
					Host:   &testHost1,
					URI:    fmt.Sprintf("/part2/%s", "103kf9wam3"),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: []string{"spec0.3", "spec0.4"},
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

	// Case 1: wildcard selection
	{
		spec := TargetGroupSpec{
			AllowedHosts: map[string]TargetHostSpec{
				testHost0: {
					TargetHost: testHost0,
					AllowedURIsForHost: []TargetURISpec{
						{
							Pattern: `^/part1/[[:alnum:]]+$`,
							PermissionsForMethod: map[string][]string{
								"GET": {"spec1.0", "spec1.1"},
								"PUT": {"spec1.2"},
							},
						},
					},
				},
				testHost1: {
					TargetHost: testHost1,
					AllowedURIsForHost: []TargetURISpec{
						{
							Pattern: `^/part2/[[:alnum:]]+$`,
							PermissionsForMethod: map[string][]string{
								"GET": {"spec1.3", "spec1.4"},
								"PUT": {"spec1.5"},
							},
						},
					},
				},
				"*": {
					TargetHost: testHost1,
					AllowedURIsForHost: []TargetURISpec{
						{
							Pattern: `^.+$`,
							PermissionsForMethod: map[string][]string{
								"GET": {"spec1.6", "spec1.7"},
								"PUT": {"spec1.8"},
							},
						},
					},
				},
			},
		}
		uut, err := DefineTargetGroupMatcher(spec)
		assert.Nil(err)

		cases := []testCase{
			{
				request: RequestParam{
					Host:   &testHost0,
					URI:    fmt.Sprintf("/part1/%s", "am9j42qmfas"),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: []string{"spec1.0", "spec1.1"},
			},
			{
				request: RequestParam{
					Host: func() *string {
						t := fmt.Sprintf("%s.unit-test.org", uuid.New().String())
						return &t
					}(),
					URI:    fmt.Sprintf("/part1/%s", "am9j42qmfas"),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: []string{"spec1.6", "spec1.7"},
			},
			{
				request: RequestParam{
					Host:   &testHost1,
					URI:    fmt.Sprintf("/part2/%s", "103kf9wam3"),
					Method: "GET",
				},
				expectedErr:         false,
				expectedPermissions: []string{"spec1.3", "spec1.4"},
			},
			{
				request: RequestParam{
					URI:    "/part3",
					Method: "PUT",
				},
				expectedErr:         false,
				expectedPermissions: []string{"spec1.8"},
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
