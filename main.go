package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/alwitt/padlock/apis"
	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/models"
	"github.com/alwitt/padlock/users"
	"github.com/apex/log"
	apexJSON "github.com/apex/log/handlers/json"
	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type cliArgs struct {
	JSONLog     bool
	LogLevel    string `validate:"required,oneof=debug info warn error"`
	ConfigFile  string `validate:"file"`
	DBParamFile string `validate:"file"`
	Hostname    string
}

var cmdArgs cliArgs

var logTags log.Fields

// @title padlock
// @version v0.1.0-rc.1
// @description REST API RBAC support application

// @host localhost:3000
// @BasePath /
// @query.collection.format multi
func main() {
	hostname, err := os.Hostname()
	if err != nil {
		log.WithError(err).Fatal("Unable to read hostname")
	}
	cmdArgs.Hostname = hostname
	logTags = log.Fields{
		"module":    "main",
		"component": "main",
		"instance":  hostname,
	}

	common.InstallDefaultAuthorizationServerConfigValues()

	app := &cli.App{
		Version:     "v0.1.0-rc.1",
		Usage:       "application entrypoint",
		Description: "A simple support application for REST API RBAC",
		Flags: []cli.Flag{
			// LOGGING
			&cli.BoolFlag{
				Name:        "json-log",
				Usage:       "Whether to log in JSON format",
				Aliases:     []string{"j"},
				EnvVars:     []string{"LOG_AS_JSON"},
				Value:       false,
				DefaultText: "false",
				Destination: &cmdArgs.JSONLog,
				Required:    false,
			},
			&cli.StringFlag{
				Name:        "log-level",
				Usage:       "Logging level: [debug info warn error]",
				Aliases:     []string{"l"},
				EnvVars:     []string{"LOG_LEVEL"},
				Value:       "warn",
				DefaultText: "warn",
				Destination: &cmdArgs.LogLevel,
				Required:    false,
			},
			// Config file
			&cli.StringFlag{
				Name:        "config-file",
				Usage:       "Application config file",
				Aliases:     []string{"c"},
				EnvVars:     []string{"CONFIG_FILE"},
				Destination: &cmdArgs.ConfigFile,
				Required:    true,
			},
			&cli.StringFlag{
				Name:        "db-param-file",
				Usage:       "Database connection parameter file",
				Aliases:     []string{"d"},
				EnvVars:     []string{"DB_CONNECT_PARAM_FILE"},
				Destination: &cmdArgs.DBParamFile,
				Required:    true,
			},
		},
		Action: mainApplication,
	}

	err = app.Run(os.Args)
	if err != nil {
		log.WithError(err).WithFields(logTags).Fatal("Program shutdown")
	}
}

func mainApplication(c *cli.Context) error {
	validate := validator.New()
	// Validate command line argument
	if err := validate.Struct(&cmdArgs); err != nil {
		log.WithError(err).WithFields(logTags).Error("Invalid CMD args")
		return err
	}

	// Setup logging
	if cmdArgs.JSONLog {
		log.SetHandler(apexJSON.New(os.Stderr))
	}
	switch cmdArgs.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.ErrorLevel)
	}

	// Process the config file
	var appCfg common.AuthorizationServerConfig
	viper.SetConfigFile(cmdArgs.ConfigFile)
	if err := viper.ReadInConfig(); err != nil {
		log.WithError(err).WithFields(logTags).
			Errorf("Failed to read config file %s", cmdArgs.ConfigFile)
		return err
	}
	if err := viper.Unmarshal(&appCfg); err != nil {
		log.WithError(err).WithFields(logTags).
			Errorf("Failed to parse config file %s", cmdArgs.ConfigFile)
		return err
	}
	{
		t, _ := json.MarshalIndent(&appCfg, "", "  ")
		log.Debugf("Application Config\n%s", t)
	}
	// Verify the application config is correct
	if err := appCfg.Validate(); err != nil {
		log.WithError(err).WithFields(logTags).
			Errorf("Application config %s is not valid", cmdArgs.ConfigFile)
		return err
	}

	// Process the database connection parameters
	var dbParam common.DatabaseConfig
	{
		context, err := ioutil.ReadFile(cmdArgs.DBParamFile)
		if err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Unable to read %s", cmdArgs.DBParamFile)
			return err
		}
		if err := json.Unmarshal(context, &dbParam); err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Unable to parse %s", cmdArgs.DBParamFile)
			return err
		}
		if err := validate.Struct(&dbParam); err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("%s content is not valid", cmdArgs.DBParamFile)
			return err
		}
	}

	customValidator, err := appCfg.Common.ValidationSupport.DefineCustomFieldValidator()
	if err != nil {
		log.WithError(err).WithFields(logTags).Errorf("Unable to define custom validator supporter")
		return err
	}

	// Create base DB client
	dbDSN := fmt.Sprintf(
		"host=%s user=%s dbname=%s sslmode=disable",
		dbParam.Host,
		dbParam.User,
		dbParam.DB,
	)
	if dbParam.Password != nil {
		dbDSN = fmt.Sprintf(
			"host=%s user=%s dbname=%s password=%s sslmode=disable",
			dbParam.Host,
			dbParam.User,
			dbParam.DB,
			*dbParam.Password,
		)
	}
	baseDBClient, err := gorm.Open(postgres.Open(dbDSN))
	if err != nil {
		log.WithError(err).WithFields(logTags).Errorf("Failed to create base DB client")
		return err
	}
	dbClient, err := models.CreateManagementDBClient(baseDBClient, customValidator)
	if err != nil {
		log.WithError(err).WithFields(logTags).Errorf("Failed to create DB client")
		return err
	}

	// Define user management client
	userManager, err := users.CreateManagement(dbClient)
	if err != nil {
		log.WithError(err).WithFields(logTags).Errorf("Failed to define user management instance")
		return err
	}

	// Synchronize role configuration
	err = userManager.AlignRolesWithConfig(context.Background(), appCfg.Roles.AvailableRoles)
	if err != nil {
		log.WithError(err).WithFields(logTags).Errorf("Failed to perform initial role config sync")
		return err
	}

	// ------------------------------------------------------------------------------------
	// Define application servers based on application configuration

	wg := sync.WaitGroup{}
	defer wg.Wait()
	apiServers := map[string]*http.Server{}

	if appCfg.API.UserAdmin.Enabled {
		svr, err := apis.BuildUserManagementServer(appCfg.API.UserAdmin, userManager, customValidator)
		if err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Unable to define User Management API HTTP Server")
			return err
		}
		apiServers["User-Management"] = svr
		// Start the server
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := svr.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.WithError(err).Error("User Management API HTTP Server Failure")
			}
		}()
	}

	// ------------------------------------------------------------------------------------
	// Wait for termination

	cc := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(cc, os.Interrupt)
	<-cc

	// Shutdown the servers
	for svrInstance, svr := range apiServers {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		if err := svr.Shutdown(ctx); err != nil {
			log.WithError(err).Errorf("Failure during HTTP Server %s shutdown", svrInstance)
		}
	}

	return nil
}
