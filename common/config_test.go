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
  rules:
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
		var cfg AuthorizationServerConfig
		assert.Nil(viper.Unmarshal(&cfg))
		assert.Nil(cfg.Validate())
	}

	// Case 2: missing parameters
	{
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
  rules:
    - host: unittest.testing.org
      paths:
        - path_pattern: "^/path1/[[:alpha:]]+/?$"
          methods:
            - allowed_permissions:
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
role:
  available_roles:
    admin:
      - all
    reader:
      assigned_permissions:
        - read
    user:
      assigned_permissions:
        - write
        - read
authorize:
  rules:
    - host: unittest.testing.org
      paths:
        - path_pattern: "^/path1/[[:alpha:]]+/?$"
          methods:
            - method: GET
              allowed_permissions:
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
role:
  available_roles:
    user:
      assigned_permissions:
        - write
        - read
        - read
authorize:
  rules:
    - host: unittest.testing.org
      paths:
        - path_pattern: "^/path1/[[:alpha:]]+/?$"
          methods:
            - method: GET
              allowed_permissions:
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
role:
  available_roles:
    admin:
      assigned_permissions:
        - all
authorize:
  rules:
    - host: unittest.testing.org
      paths:
        - path_pattern: "^/path1/[[:alpha:]]+/?$"
          methods:
            - method: GET
              allowed_permissions:
                - all
    - host: unittest.testing.org
      paths:
        - path_pattern: "^/path2/[[:alpha:]]+/$"
          methods:
            - method: PUT
              allowed_permissions:
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
role:
  available_roles:
    admin:
      assigned_permissions:
        - all
authorize:
  rules:
    - host: unittest.testing.org
      paths:
        - path_pattern: "^/path1/[[:alpha:]]+/?$"
          methods:
            - method: GET
              allowed_permissions:
                - all
        - path_pattern: "^/path1/[[:alpha:]]+/?$"
          methods:
            - method: PUT
              allowed_permissions:
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
role:
  available_roles:
    admin:
      assigned_permissions:
        - all
authorize:
  rules:
    - host: unittest.testing.org
      paths:
        - path_pattern: "^/path1/[[:alpha:]]+/?$"
          methods:
            - method: GET
              allowed_permissions:
                - all
            - method: GET
              allowed_permissions:
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
role:
  available_roles:
    admin:
      assigned_permissions:
        - all
authorize:
  rules:
    - host: unittest.testing.org
      paths:
        - path_pattern: "^/path1/[[:alpha:]]+/?$"
          methods:
            - method: GET
              allowed_permissions:
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
role:
  available_roles:
    admin:
      assigned_permissions:
        - all
authorize:
  rules:
    - host: unittest.testing.org
      paths:
        - path_pattern: "^/path1/[[:alpha:]]+/?$"
          methods:
            - method: GET
              allowed_permissions:
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
role:
  available_roles:
    admin:
      assigned_permissions:
        - all
        - "read.path1"
authorize:
  rules:
    - host: unittest.testing.org
      paths:
        - path_pattern: "^/path1/[[:alpha:]]+/?$"
          methods:
            - method: GET
              allowed_permissions:
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
role:
  available_roles:
    "admin+local":
      assigned_permissions:
        - all
authorize:
  rules:
    - host: unittest.testing.org
      paths:
        - path_pattern: "^/path1/[[:alpha:]]+/?$"
          methods:
            - method: GET
              allowed_permissions:
                - all
                - read`)
		viper.SetConfigType("yaml")
		err := viper.ReadConfig(bytes.NewBuffer(config))
		assert.Nil(err)
		var cfg AuthorizationServerConfig
		assert.Nil(viper.Unmarshal(&cfg))
		assert.NotNil(cfg.Validate())
	}
}
