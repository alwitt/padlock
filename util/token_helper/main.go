// Package main - OAuth token utility application
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/alwitt/goutils"
	"github.com/alwitt/padlock/common"
	"github.com/apex/log"
	apexJSON "github.com/apex/log/handlers/json"
	"github.com/go-playground/validator/v10"
	"github.com/urfave/cli/v2"
)

type cliArgs struct {
	JSONLog               bool
	LogLevel              string `validate:"required,oneof=debug info warn error"`
	OpenIDIssuerParamFile string `validate:"omitempty,file"`
	Hostname              string
}

var cmdArgs cliArgs

var logTags log.Fields

var accessTokenAudience string

func main() {
	hostname, err := os.Hostname()
	if err != nil {
		log.WithError(err).Fatal("Unable to read hostname")
	}
	cmdArgs.Hostname = hostname
	logTags = log.Fields{
		"module":    "main",
		"component": "token-helper",
		"instance":  hostname,
	}

	app := &cli.App{
		Version:     "v0.1.0",
		Usage:       "application entrypoint",
		Description: "OAuth token utility application",
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
				Name:        "openid-issuer-param-file",
				Usage:       "OpenID issuer parameter file",
				Aliases:     []string{"o"},
				EnvVars:     []string{"OPENID_ISSUER_PARAM_FILE"},
				Destination: &cmdArgs.OpenIDIssuerParamFile,
				Required:    false,
			},
		},
		Commands: []*cli.Command{
			{
				Name:        "get",
				Usage:       "fetch token",
				Description: "Acquire new access token using client credential flow",
				Action:      getNewToken,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "audience",
						Usage:       "Target audience of the token",
						Aliases:     []string{"a"},
						EnvVars:     []string{"TARGET_TOKEN_AUDIENCE"},
						Value:       "",
						DefaultText: "",
						Destination: &accessTokenAudience,
						Required:    false,
					},
				},
			},
		},
	}

	err = app.Run(os.Args)
	if err != nil {
		log.WithError(err).WithFields(logTags).Fatal("Program shutdown")
	}
}

func getNewToken(ctx *cli.Context) error {
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

	oidpHTTPClient, err := goutils.DefineHTTPClient(
		ctx.Context,
		goutils.HTTPClientRetryConfig{
			MaxAttempts:  6,
			InitWaitTime: 5,
			MaxWaitTime:  30,
		},
		nil,
		&goutils.HTTPClientTransportConfig{CustomCA: oidParam.CustomCA},
	)
	if err != nil {
		return fmt.Errorf("unable to define HTTP client for oauth token manager[%w]", err)
	}

	tokenParams := goutils.ClientCredOAuthTokenManagerParam{
		IDPIssuerURL: oidParam.Issuer,
		ClientID:     *oidParam.ClientID,
		ClientSecret: *oidParam.ClientCred,
		LogTags: log.Fields{
			"module":    "main",
			"component": "token-manger",
		},
		TimeBuffer: time.Minute,
	}
	if accessTokenAudience != "" {
		tokenParams.TargetAudience = &accessTokenAudience
	}
	tokenMgmt, err := goutils.GetNewClientCredOAuthTokenManager(
		ctx.Context, oidpHTTPClient, tokenParams,
	)
	if err != nil {
		return fmt.Errorf("unable to define oauth token manager [%w]", err)
	}

	newToken, err := tokenMgmt.GetToken(ctx.Context, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("unable to acquire new token from manager [%w]", err)
	}

	fmt.Printf("\n%s\n", newToken)

	return tokenMgmt.Stop(ctx.Context)
}
