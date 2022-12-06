package common

import (
	"bytes"
	"testing"

	"github.com/apex/log"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizationServerConfig(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	// Case 0: parse config with no defaults in place
	{
		cfg := AuthorizationServerConfig{}
		assert.NotNil(cfg.Validate())
	}

	InstallDefaultAuthorizationServerConfigValues()

	// Case 1: basic valid configuration
	{
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
		var cfg AuthorizationServerConfig
		assert.Nil(viper.Unmarshal(&cfg))
		assert.Nil(cfg.Validate())
	}

	// Case 2: missing parameters
	{
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
            - allowedPermissions:
                - all
                - read`)
		viper.SetConfigType("yaml")
		assert.Nil(viper.ReadConfig(bytes.NewBuffer(config)))
		var cfg AuthorizationServerConfig
		assert.Nil(viper.Unmarshal(&cfg))
		assert.NotNil(cfg.Validate())
	}

	// Case 3: bad structure
	{
		config := []byte(`---
userManagement:
  userRoles:
    admin:
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
                - read`)
		viper.SetConfigType("yaml")
		assert.Nil(viper.ReadConfig(bytes.NewBuffer(config)))
		var cfg AuthorizationServerConfig
		assert.NotNil(viper.Unmarshal(&cfg))
	}

	// Case 4: duplicate entries in roles
	{
		config := []byte(`---
userManagement:
  userRoles:
    user:
      permissions:
        - write
        - read
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
                - read`)
		viper.SetConfigType("yaml")
		err := viper.ReadConfig(bytes.NewBuffer(config))
		assert.Nil(err)
		var cfg AuthorizationServerConfig
		assert.Nil(viper.Unmarshal(&cfg))
		assert.NotNil(cfg.Validate())
	}

	// Case 5: duplicate entries in hosts
	{
		config := []byte(`---
userManagement:
  userRoles:
    admin:
      permissions:
        - all
authorize:
  rules:
    - host: unittest.testing.org
      allowedPaths:
        - pathPattern: "^/path1/[[:alpha:]]+/?$"
          allowedMethods:
            - method: GET
              allowedPermissions:
                - all
    - host: unittest.testing.org
      allowedPaths:
        - pathPattern: "^/path2/[[:alpha:]]+/$"
          allowedMethods:
            - method: PUT
              allowedPermissions:
                - all`)
		viper.SetConfigType("yaml")
		err := viper.ReadConfig(bytes.NewBuffer(config))
		assert.Nil(err)
		var cfg AuthorizationServerConfig
		assert.Nil(viper.Unmarshal(&cfg))
		assert.NotNil(cfg.Validate())
	}

	// Case 6: duplicate entries in paths
	{
		config := []byte(`---
userManagement:
  userRoles:
    admin:
      permissions:
        - all
authorize:
  rules:
    - host: unittest.testing.org
      allowedPaths:
        - pathPattern: "^/path1/[[:alpha:]]+/?$"
          allowedMethods:
            - method: GET
              allowedPermissions:
                - all
        - pathPattern: "^/path1/[[:alpha:]]+/?$"
          allowedMethods:
            - method: PUT
              allowedPermissions:
                - all`)
		viper.SetConfigType("yaml")
		err := viper.ReadConfig(bytes.NewBuffer(config))
		assert.Nil(err)
		var cfg AuthorizationServerConfig
		assert.Nil(viper.Unmarshal(&cfg))
		assert.NotNil(cfg.Validate())
	}

	// Case 7: duplicate entries in path methods
	{
		config := []byte(`---
userManagement:
  userRoles:
    admin:
      permissions:
        - all
authorize:
  rules:
    - host: unittest.testing.org
      allowedPaths:
        - pathPattern: "^/path1/[[:alpha:]]+/?$"
          allowedMethods:
            - method: GET
              allowedPermissions:
                - all
            - method: GET
              allowedPermissions:
                - all`)
		viper.SetConfigType("yaml")
		err := viper.ReadConfig(bytes.NewBuffer(config))
		assert.Nil(err)
		var cfg AuthorizationServerConfig
		assert.Nil(viper.Unmarshal(&cfg))
		assert.NotNil(cfg.Validate())
	}

	// Case 8: duplicate entries in permission for path methods
	{
		config := []byte(`---
userManagement:
  userRoles:
    admin:
      permissions:
        - all
authorize:
  rules:
    - host: unittest.testing.org
      allowedPaths:
        - pathPattern: "^/path1/[[:alpha:]]+/?$"
          allowedMethods:
            - method: GET
              allowedPermissions:
                - all
                - all`)
		viper.SetConfigType("yaml")
		err := viper.ReadConfig(bytes.NewBuffer(config))
		assert.Nil(err)
		var cfg AuthorizationServerConfig
		assert.Nil(viper.Unmarshal(&cfg))
		assert.NotNil(cfg.Validate())
	}

	// Case 9: permission for path method is not associated with any roles
	{
		config := []byte(`---
userManagement:
  userRoles:
    admin:
      permissions:
        - all
authorize:
  rules:
    - host: unittest.testing.org
      allowedPaths:
        - pathPattern: "^/path1/[[:alpha:]]+/?$"
          allowedMethods:
            - method: GET
              allowedPermissions:
                - all
                - read`)
		viper.SetConfigType("yaml")
		err := viper.ReadConfig(bytes.NewBuffer(config))
		assert.Nil(err)
		var cfg AuthorizationServerConfig
		assert.Nil(viper.Unmarshal(&cfg))
		assert.NotNil(cfg.Validate())
	}

	// Case 10: regex failures on permission name
	{
		config := []byte(`---
userManagement:
  userRoles:
    admin:
      permissions:
        - all
        - "read.path1"
authorize:
  rules:
    - host: unittest.testing.org
      allowedPaths:
        - pathPattern: "^/path1/[[:alpha:]]+/?$"
          allowedMethods:
            - method: GET
              allowedPermissions:
                - all
                - read`)
		viper.SetConfigType("yaml")
		err := viper.ReadConfig(bytes.NewBuffer(config))
		assert.Nil(err)
		var cfg AuthorizationServerConfig
		assert.Nil(viper.Unmarshal(&cfg))
		assert.NotNil(cfg.Validate())
	}

	// Case 11: regex failures on role name
	{
		config := []byte(`---
userManagement:
  userRoles:
    "admin+local":
      permissions:
        - all
authorize:
  rules:
    - host: unittest.testing.org
      allowedPaths:
        - pathPattern: "^/path1/[[:alpha:]]+/?$"
          allowedMethods:
            - method: GET
              allowedPermissions:
                - all
                - read`)
		viper.SetConfigType("yaml")
		err := viper.ReadConfig(bytes.NewBuffer(config))
		assert.Nil(err)
		var cfg AuthorizationServerConfig
		assert.Nil(viper.Unmarshal(&cfg))
		assert.NotNil(cfg.Validate())
	}

	// Case 12: disable authorization server
	{
		config := []byte(`---
userManagement:
  userRoles:
    user:
      permissions:
        - write
        - read
authorize:
  enabled: false`)
		viper.SetConfigType("yaml")
		err := viper.ReadConfig(bytes.NewBuffer(config))
		assert.Nil(err)
		var cfg AuthorizationServerConfig
		assert.Nil(viper.Unmarshal(&cfg))
		assert.Nil(cfg.Validate())
	}

	// Case 13: disable authorization and user management server, authentication server config given
	{
		config := []byte(`---
userManagement:
  enabled: false
authorize:
  enabled: false
authenticate:
  enabled: true
  introspect:
    cacheCleanIntervalSec: 10`)
		viper.SetConfigType("yaml")
		err := viper.ReadConfig(bytes.NewBuffer(config))
		assert.Nil(err)
		var cfg AuthorizationServerConfig
		assert.Nil(viper.Unmarshal(&cfg))
		assert.NotNil(cfg.Validate())
	}
}
