package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/alwitt/goutils"
	"github.com/alwitt/padlock/apis"
	"github.com/alwitt/padlock/authenticate"
	"github.com/alwitt/padlock/common"
	"github.com/alwitt/padlock/match"
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
	JSONLog               bool
	LogLevel              string `validate:"required,oneof=debug info warn error"`
	ConfigFile            string `validate:"file"`
	DBParamFile           string `validate:"omitempty,file"`
	DBPassword            string
	OpenIDIssuerParamFile string `validate:"omitempty,file"`
	Hostname              string
}

var cmdArgs cliArgs

var logTags log.Fields

// @title padlock
// @version v0.5.0
// @description External AuthN / AuthZ support service for REST API RBAC

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
		Version:     "v0.5.0",
		Usage:       "application entrypoint",
		Description: "An external AuthN / AuthZ support service for REST API RBAC",
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
				Required:    false,
			},
			&cli.StringFlag{
				Name:        "db-user-password",
				Usage:       "Database user password",
				Aliases:     []string{"p"},
				EnvVars:     []string{"DB_CONNECT_USER_PASSWORD"},
				Value:       "",
				DefaultText: "",
				Destination: &cmdArgs.DBPassword,
				Required:    false,
			},
			&cli.StringFlag{
				Name:        "openid-issuer-param-file",
				Usage:       "OpenID issuer parameter file",
				Aliases:     []string{"o"},
				EnvVars:     []string{"OPENID_ISSUER_PARAM_FILE"},
				Destination: &cmdArgs.OpenIDIssuerParamFile,
				Required:    false,
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

	customValidator, err := appCfg.CustomRegex.DefineCustomFieldValidator()
	if err != nil {
		log.WithError(err).WithFields(logTags).Errorf("Unable to define custom validator supporter")
		return err
	}

	var userManager users.Management
	// Only define user management module if either the
	//  * user management service
	//  * user authorization service is enabled
	if appCfg.UserManagement.Enabled || appCfg.Authorization.Enabled {
		// Process the database connection parameters
		var dbParam common.DatabaseConfig
		{
			params, err := os.ReadFile(cmdArgs.DBParamFile)
			if err != nil {
				log.WithError(err).WithFields(logTags).Errorf("Unable to read %s", cmdArgs.DBParamFile)
				return err
			}
			if err := json.Unmarshal(params, &dbParam); err != nil {
				log.WithError(err).WithFields(logTags).Errorf("Unable to parse %s", cmdArgs.DBParamFile)
				return err
			}
			if err := validate.Struct(&dbParam); err != nil {
				log.WithError(err).WithFields(logTags).
					Errorf("%s content is not valid", cmdArgs.DBParamFile)
				return err
			}
		}

		// Create base DB client
		dbDSN := fmt.Sprintf(
			"host=%s user=%s dbname=%s sslmode=disable",
			dbParam.Host,
			dbParam.User,
			dbParam.DB,
		)
		if cmdArgs.DBPassword != "" {
			dbDSN = fmt.Sprintf(
				"host=%s user=%s dbname=%s password=%s sslmode=disable",
				dbParam.Host,
				dbParam.User,
				dbParam.DB,
				cmdArgs.DBPassword,
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
		userManager, err = users.CreateManagement(dbClient)
		if err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Failed to define user management instance")
			return err
		}

		// Synchronize role configuration
		err = userManager.AlignRolesWithConfig(
			context.Background(), appCfg.UserManagement.AvailableRoles,
		)
		if err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Failed to perform initial role config sync")
			return err
		}
	}

	// ------------------------------------------------------------------------------------
	// Define application servers based on application configuration

	wg := sync.WaitGroup{}
	defer wg.Wait()
	apiServers := map[string]*http.Server{}
	cleanUpTasks := map[string]func() error{}

	defer func() {
		// Shutdown the servers
		for svrInstance, svr := range apiServers {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			defer cancel()
			if err := svr.Shutdown(ctx); err != nil {
				log.WithError(err).Errorf("Failure during HTTP Server %s shutdown", svrInstance)
			}
		}
		// Perform other clean up tasks
		for taskName, task := range cleanUpTasks {
			if err := task(); err != nil {
				log.WithError(err).Errorf("Clean up task '%s' failed", taskName)
			}
		}
	}()

	metrics, err := newMetricsCollector(appCfg.Metrics.Features)
	if err != nil {
		log.
			WithError(err).
			WithFields(logTags).
			Error("Failed to create metrics collector")
		return err
	}
	httpMetricsAgent := metrics.InstallHTTPMetrics()

	{
		svr, err := apis.BuildMetricsCollectionServer(
			appCfg.Metrics.Server, metrics, appCfg.Metrics.MetricsEndpoint, appCfg.Metrics.MaxRequests,
		)
		if err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Unable to define metrics HTTP Server")
			return err
		}
		apiServers["Metrics"] = svr
		// Start the server
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := svr.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.WithError(err).Error("Metrics HTTP Server Failure")
			}
		}()
	}

	if appCfg.UserManagement.Enabled {
		svr, err := apis.BuildUserManagementServer(
			appCfg.UserManagement.APIServerConfig, userManager, customValidator, httpMetricsAgent,
		)
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

	if appCfg.Authorization.Enabled {
		// Build request matcher
		matcherSpec, err := match.ConvertConfigToTargetGroupSpec(
			&appCfg.Authorization.AuthorizationConfig,
		)
		if err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Unable to define request matcher spec")
			return err
		}
		matcher, err := match.DefineTargetGroupMatcher(matcherSpec)
		if err != nil {
			log.WithError(err).WithFields(logTags).Errorf("Unable to define request matcher")
			return err
		}
		svr, err := apis.BuildAuthorizationServer(
			appCfg.Authorization.APIServerConfig,
			userManager,
			matcher,
			customValidator,
			appCfg.Authorization.RequestParamLocation,
			appCfg.Authorization.UnknownUser,
			httpMetricsAgent,
		)
		if err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Unable to define Authorization API HTTP Server")
			return err
		}
		apiServers["Authorization"] = svr
		// Start the server
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := svr.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.WithError(err).Error("Authorization API HTTP Server Failure")
			}
		}()
	}

	if appCfg.Authentication.Enabled {
		if cmdArgs.OpenIDIssuerParamFile == "" {
			return fmt.Errorf("no OpenID issuer parameter file given")
		}
		// Parse OpenID issuer parameter file
		var oidParam common.OpenIDIssuerConfig
		params, err := os.ReadFile(cmdArgs.OpenIDIssuerParamFile)
		if err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Unable to read %s", cmdArgs.OpenIDIssuerParamFile)
			return err
		}
		if err := json.Unmarshal(params, &oidParam); err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Unable to parse %s", cmdArgs.OpenIDIssuerParamFile)
			return err
		}
		if err := validate.Struct(&oidParam); err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("%s content is not valid", cmdArgs.OpenIDIssuerParamFile)
			return err
		}
		// Token cache in support of introspection
		tokenCache := authenticate.DefineTokenCache(
			time.Second * time.Duration(appCfg.Authentication.Introspection.ReIntrospectInterval),
		)
		// Timer to clear out expired tokens from the cache
		expireTokenCleanupTimer, err := goutils.GetIntervalTimerInstance(
			context.Background(), &wg, log.Fields{
				"module":    "main",
				"component": "timer",
				"instance":  "expired-token-cleanup",
			},
		)
		if err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Unable to define expired-token-cleanup timer")
			return err
		}
		// Start timer to clear out expired tokens from the cache
		if err := expireTokenCleanupTimer.Start(time.Second*time.Duration(
			appCfg.Authentication.Introspection.CacheCleanInterval), func() error {
			err := tokenCache.RemoveExpiredFromCache(context.Background(), time.Now().UTC())
			if err != nil {
				log.WithError(err).WithFields(logTags).Error("Expired token cleanup in cache failed")
			}
			return err
		}, false,
		); err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Unable to start expired-token-cleanup timer")
			return err
		}
		// Stop the expired token cleanup timer on exit
		cleanUpTasks["Stop expired-token-cache-cleanup timer"] = func() error {
			return expireTokenCleanupTimer.Stop()
		}
		// Timer to purge token cache
		tokenCachePurgeTimer, err := goutils.GetIntervalTimerInstance(
			context.Background(), &wg, log.Fields{
				"module":    "main",
				"component": "timer",
				"instance":  "token-cache-purge",
			},
		)
		if err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Unable to define token-cache-purge timer")
			return err
		}
		// Start timer to purge token cache
		if err := tokenCachePurgeTimer.Start(time.Second*time.Duration(
			appCfg.Authentication.Introspection.CachePurgeInterval), func() error {
			err := tokenCache.RemoveExpiredFromCache(context.Background(), time.Now().UTC())
			if err != nil {
				log.WithError(err).WithFields(logTags).Error("Token cache purge failed")
			}
			return err
		}, false,
		); err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Unable to start token-cache-purge timer")
			return err
		}
		// Stop the token cache purge timer on exit
		cleanUpTasks["Stop token-cache-purge timer"] = func() error {
			return tokenCachePurgeTimer.Stop()
		}
		svr, err := apis.BuildAuthenticationServer(
			appCfg.Authentication.APIServerConfig,
			oidParam,
			appCfg.Authentication.Introspection.Enabled,
			tokenCache,
			appCfg.Authentication.AuthenticationConfig,
			appCfg.Authorization.RequestParamLocation,
			httpMetricsAgent,
		)
		if err != nil {
			log.WithError(err).WithFields(logTags).
				Errorf("Unable to define Authentication API HTTP Server")
			return err
		}
		apiServers["Authentication"] = svr
		// Start the server
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := svr.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.WithError(err).Error("Authentication API HTTP Server Failure")
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

	return nil
}

// newMetricsCollector define metrics collector
func newMetricsCollector(config common.MetricsFeatureConfig) (goutils.MetricsCollector, error) {
	framework, err := goutils.GetNewMetricsCollector(
		log.Fields{"module": "goutils", "component": "metrics-core"}, []goutils.LogMetadataModifier{},
	)
	if err != nil {
		return nil, err
	}
	if config.EnableAppMetrics {
		framework.InstallApplicationMetrics()
	}
	return framework, nil
}
