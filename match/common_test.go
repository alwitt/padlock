package match

import (
	"bytes"
	"testing"

	"github.com/alwitt/padlock/common"
	"github.com/apex/log"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizationConfigConvert(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	common.InstallDefaultAuthorizationServerConfigValues()

	config := []byte(`---
role:
  available_roles:
    admin:
      assigned_permissions:
        - all
    reader:
      assigned_permissions:
        - read
    user:
      assigned_permissions:
        - write
        - read
authorize:
  hosts:
    - host: unittest.testing.org
      paths:
        - path_pattern: "^/path1/[[:alpha:]]+/?$"
          methods:
            - method: GET
              allowed_permissions:
                - all
                - read
            - method: PUT
              allowed_permissions:
                - all
                - write
        - path_pattern: "^/path2/[[:alnum:]]+/$"
          methods:
            - method: "*"
              allowed_permissions:
                - all
                - read
    - host: "*"
      paths:
        - path_pattern: "^/path3/[[:alpha:]]+/?$"
          methods:
            - method: POST
              allowed_permissions:
                - all
                - write`)
	viper.SetConfigType("yaml")
	assert.Nil(viper.ReadConfig(bytes.NewBuffer(config)))
	var cfg common.AuthorizationServerConfig
	assert.Nil(viper.Unmarshal(&cfg))
	assert.Nil(cfg.Validate())

	groupSpec, err := ConvertConfigToTargetGroupSpec(&cfg.Authorize)
	assert.Nil(err)

	assert.Len(groupSpec.AllowedHosts, 2)
	_, ok := groupSpec.AllowedHosts["*"]
	assert.True(ok)
	_, ok = groupSpec.AllowedHosts["unittest.testing.org"]
	assert.True(ok)

	assert.Equal("unittest.testing.org", groupSpec.AllowedHosts["unittest.testing.org"].TargetHost)
	assert.Len(groupSpec.AllowedHosts["unittest.testing.org"].AllowedPathsForHost, 2)
	{
		paths := groupSpec.AllowedHosts["unittest.testing.org"].AllowedPathsForHost
		assert.Equal("^/path1/[[:alpha:]]+/?$", paths[0].PathPattern)
		assert.Len(paths[0].PermissionsForMethod, 2)
		getMethodPerm, ok := paths[0].PermissionsForMethod["GET"]
		assert.True(ok)
		assert.Equal([]string{"all", "read"}, getMethodPerm)
		putMethodPerm, ok := paths[0].PermissionsForMethod["PUT"]
		assert.True(ok)
		assert.Equal([]string{"all", "write"}, putMethodPerm)
		assert.Equal("^/path2/[[:alnum:]]+/$", paths[1].PathPattern)
		assert.Len(paths[1].PermissionsForMethod, 1)
		wildcardMethodPerm, ok := paths[1].PermissionsForMethod["*"]
		assert.True(ok)
		assert.Equal([]string{"all", "read"}, wildcardMethodPerm)
	}

	assert.Equal("*", groupSpec.AllowedHosts["*"].TargetHost)
	assert.Len(groupSpec.AllowedHosts["*"].AllowedPathsForHost, 1)
	{
		paths := groupSpec.AllowedHosts["*"].AllowedPathsForHost
		assert.Equal("^/path3/[[:alpha:]]+/?$", paths[0].PathPattern)
		assert.Len(paths[0].PermissionsForMethod, 1)
		postMethodPerm, ok := paths[0].PermissionsForMethod["POST"]
		assert.True(ok)
		assert.Equal([]string{"all", "write"}, postMethodPerm)
	}
}
