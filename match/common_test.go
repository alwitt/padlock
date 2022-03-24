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
userManagement:
  userRoles:
    admin:
      permissions:
        - all
    reader:
      permissions:
        - read
    user:
      permissions:
        - write
        - read
authorize:
  rules:
    - host: unittest.testing.org
      allowedPaths:
        - pathPattern: "^/path1/[[:alpha:]]+/?$"
          allowedMethods:
            - method: GET
              allowedPermissions:
                - all
                - read
            - method: PUT
              allowedPermissions:
                - all
                - write
        - pathPattern: "^/path2/[[:alnum:]]+/$"
          allowedMethods:
            - method: "*"
              allowedPermissions:
                - all
                - read
    - host: "*"
      allowedPaths:
        - pathPattern: "^/path3/[[:alpha:]]+/?$"
          allowedMethods:
            - method: POST
              allowedPermissions:
                - all
                - write`)
	viper.SetConfigType("yaml")
	assert.Nil(viper.ReadConfig(bytes.NewBuffer(config)))
	var cfg common.AuthorizationServerConfig
	assert.Nil(viper.Unmarshal(&cfg))
	assert.Nil(cfg.Validate())

	groupSpec, err := ConvertConfigToTargetGroupSpec(&cfg.Authorization.AuthorizationConfig)
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
