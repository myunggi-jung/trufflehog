package main

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"

	"encoding/json"

	"github.com/aws/aws-lambda-go/lambda"
	//"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	slackMessage "github.com/slack-go/slack"

	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/jpillora/overseer"

	"trufflehog/pkg/engine"
	"trufflehog/pkg/output"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/version"
)

var (
	s3ScanKey           string
	s3ScanRoleArns      []string
	s3ScanSecret        string
	s3ScanSessionToken  string
	s3ScanCloudEnv      bool
	s3ScanBuckets       []string
	s3ScanMaxObjectSize int64

	roleArns      string
	maxObjectSize string
)

type MyEvent struct {
	Name string `json:"name"`
}

func HandleRequest(event *MyEvent) (*string, error) {
	if event == nil {
		return nil, fmt.Errorf("received nil event")
	}
	message := fmt.Sprintf("Hello %s!", event.Name)
	// setup logger
	logFormat := log.WithConsoleSink
	logger, sync := log.New("trufflehog", logFormat(os.Stderr))

	// make it the default logger for contexts
	context.SetDefaultLogger(logger)

	if os.Getenv("local") == "true" {
		run(overseer.State{})
		os.Exit(0)
	}

	defer func() { _ = sync() }()
	logFatal := logFatalFunc(logger)

	updateCfg := overseer.Config{
		Program:       run,
		Debug:         false,
		RestartSignal: syscall.SIGTERM,
		// TODO: Eventually add a PreUpgrade func for signature check w/ x509 PKCS1v15
		// PreUpgrade: checkUpdateSignature(binaryPath string),
	}
	err := overseer.RunErr(updateCfg)
	if err != nil {
		logFatal(err, "error occurred with trufflehog updater 🐷")
	}
	return &message, nil
}

func main() {
	lambda.Start(HandleRequest)
	//// setup logger
	//logFormat := log.WithConsoleSink
	//logger, sync := log.New("trufflehog", logFormat(os.Stderr))
	//
	//// make it the default logger for contexts
	//context.SetDefaultLogger(logger)
	//
	//if os.Getenv("local") == "true" {
	//	run(overseer.State{})
	//	os.Exit(0)
	//}
	//
	//defer func() { _ = sync() }()
	//logFatal := logFatalFunc(logger)
	//
	//updateCfg := overseer.Config{
	//	Program:       run,
	//	Debug:         false,
	//	RestartSignal: syscall.SIGTERM,
	//	// TODO: Eventually add a PreUpgrade func for signature check w/ x509 PKCS1v15
	//	// PreUpgrade: checkUpdateSignature(binaryPath string),
	//}
	//err := overseer.RunErr(updateCfg)
	//if err != nil {
	//	logFatal(err, "error occurred with trufflehog updater 🐷")
	//}
}

func run(state overseer.State) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	go func() {
		if err := cleantemp.CleanTempArtifacts(ctx); err != nil {
			ctx.Logger().Error(err, "error cleaning temporary artifacts")
		}
	}()

	logger := ctx.Logger()
	logFatal := logFatalFunc(logger)

	killSignal := make(chan os.Signal, 1)
	signal.Notify(killSignal, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-killSignal
		logger.Info("Received signal, shutting down.")
		cancel(fmt.Errorf("canceling context due to signal"))

		if err := cleantemp.CleanTempArtifacts(ctx); err != nil {
			logger.Error(err, "error cleaning temporary artifacts")
		} else {
			logger.Info("cleaned temporary artifacts")
		}

		time.Sleep(time.Second * 10)
		logger.Info("10 seconds elapsed. Forcing shutdown.")
		os.Exit(0)
	}()

	logger.V(2).Info(fmt.Sprintf("trufflehog %s", version.BuildVersion))

	conf := &config.Config{}

	// Build include and exclude detector sets for filtering on engine initialization.
	// Exit if there was an error to inform the user of the misconfiguration.
	var includeDetectorSet, excludeDetectorSet map[config.DetectorID]struct{}
	var detectorsWithCustomVerifierEndpoints map[config.DetectorID][]string
	{
		includeList, err := config.ParseDetectors("all")
		if err != nil {
			logFatal(err, "invalid include list detector configuration")
		}
		excludeList, err := config.ParseDetectors("")
		if err != nil {
			logFatal(err, "invalid exclude list detector configuration")
		}
		detectorsWithCustomVerifierEndpoints, err = config.ParseVerifierEndpoints(nil)
		if err != nil {
			logFatal(err, "invalid verifier detector configuration")
		}
		includeDetectorSet = detectorTypeToSet(includeList)
		excludeDetectorSet = detectorTypeToSet(excludeList)
	}

	// Verify that all the user-provided detectors support the optional
	// detector features.
	{
		if err, id := verifyDetectorsAreVersioner(includeDetectorSet); err != nil {
			logFatal(err, "invalid include list detector configuration", "detector", id)
		}
		if err, id := verifyDetectorsAreVersioner(excludeDetectorSet); err != nil {
			logFatal(err, "invalid exclude list detector configuration", "detector", id)
		}
		if err, id := verifyDetectorsAreVersioner(detectorsWithCustomVerifierEndpoints); err != nil {
			logFatal(err, "invalid verifier detector configuration", "detector", id)
		}
		// Extra check for endpoint customization.
		isEndpointCustomizer := engine.DefaultDetectorTypesImplementing[detectors.EndpointCustomizer]()
		for id := range detectorsWithCustomVerifierEndpoints {
			if _, ok := isEndpointCustomizer[id.ID]; !ok {
				logFatal(
					fmt.Errorf("endpoint provided but detector does not support endpoint customization"),
					"invalid custom verifier endpoint detector configuration",
					"detector", id,
				)
			}
		}
	}

	includeFilter := func(d detectors.Detector) bool {
		_, ok := getWithDetectorID(d, includeDetectorSet)
		return ok
	}
	excludeFilter := func(d detectors.Detector) bool {
		_, ok := getWithDetectorID(d, excludeDetectorSet)
		return !ok
	}
	// Abuse filter to cause a side-effect.
	endpointCustomizer := func(d detectors.Detector) bool {
		urls, ok := getWithDetectorID(d, detectorsWithCustomVerifierEndpoints)
		if !ok {
			return true
		}
		id := config.GetDetectorID(d)
		customizer, ok := d.(detectors.EndpointCustomizer)
		if !ok {
			// NOTE: We should never reach here due to validation above.
			logFatal(
				fmt.Errorf("failed to configure a detector endpoint"),
				"the provided detector does not support endpoint configuration",
				"detector", id,
			)
		}
		if err := customizer.SetEndpoints(urls...); err != nil {
			logFatal(err, "failed configuring custom endpoint for detector", "detector", id)
		}
		logger.Info("configured detector with verification urls",
			"detector", id, "urls", urls,
		)
		return true
	}

	// Set how the engine will print its results.
	var printer engine.Printer
	printer = new(output.PlainPrinter)
	// setup aws
	s3ScanCloudEnv = false
	maxObjectSize = os.Getenv("MAX_OBJECT_SIZE")
	if maxObjectSize == "" {
		maxObjectSize = "262144000"
	}
	s3ScanMaxObjectSize, _ = strconv.ParseInt(maxObjectSize, 10, 64)

	s3ScanKey = os.Getenv("AWS_ACCESS_KEY_ID")
	s3ScanSecret = os.Getenv("AWS_SECRET_ACCESS_KEY")
	s3ScanSessionToken = os.Getenv("AWS_SESSION_TOKEN")
	roleArns = os.Getenv("AWS_ROLE_ARNS")
	s3ScanRoleArns = strings.Split(roleArns, ",")
	//slackUrl := getSlackWebhook(s3ScanKey, s3ScanSecret, s3ScanSessionToken)
	teamsUrl := getTeamsWebhook(s3ScanKey, s3ScanSecret, s3ScanSessionToken)

	fmt.Fprintf(os.Stderr, "🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷\n\n")
	//sendSlackMessage(url, "TruffleHog. Unearth your secrets.")

	e, err := engine.Start(ctx,
		engine.WithConcurrency(uint8(10)),
		engine.WithDecoders(decoders.DefaultDecoders()...),
		engine.WithDetectors(engine.DefaultDetectors()...),
		engine.WithDetectors(conf.Detectors...),
		engine.WithVerify(true),
		engine.WithFilterDetectors(includeFilter),
		engine.WithFilterDetectors(excludeFilter),
		engine.WithFilterDetectors(endpointCustomizer),
		engine.WithFilterUnverified(false),
		engine.WithOnlyVerified(false),
		engine.WithPrintAvgDetectorTime(false),
		engine.WithPrinter(printer),
		engine.WithFilterEntropy(0),
	)
	if err != nil {
		logFatal(err, "error initializing engine")
	}

	cfg := sources.S3Config{
		Key:           s3ScanKey,
		Secret:        s3ScanSecret,
		SessionToken:  s3ScanSessionToken,
		Buckets:       s3ScanBuckets,
		Roles:         s3ScanRoleArns,
		CloudCred:     s3ScanCloudEnv,
		MaxObjectSize: s3ScanMaxObjectSize,
	}
	if err := e.ScanS3(ctx, cfg); err != nil {
		logFatal(err, "Failed to scan S3.")
	}

	// Wait for all workers to finish.
	if err = e.Finish(ctx); err != nil {
		logFatal(err, "engine failed to finish execution")
	}

	metrics := e.GetMetrics()
	// Print results.
	logger.Info("finished scanning",
		"chunks", metrics.ChunksScanned,
		"bytes", metrics.BytesScanned,
		"verified_secrets", metrics.VerifiedSecretsFound,
		"unverified_secrets", metrics.UnverifiedSecretsFound,
		"scan_duration", metrics.ScanDuration.String(),
	)

	//slack message
	//sendSlackMessage(slackUrl, fmt.Sprintf("finished scanning \tchunks: %d, bytes: %d, verified_secrets: %d, unverified_secrets: %d, scan_duration: %s", metrics.ChunksScanned, metrics.BytesScanned, metrics.VerifiedSecretsFound, metrics.UnverifiedSecretsFound, metrics.ScanDuration.String()))
	//teams message
	sendTeamsMessage(teamsUrl, "S3 secret scanning result", fmt.Sprintf("finished scanning \tchunks: %d, bytes: %d, verified_secrets: %d, unverified_secrets: %d, scan_duration: %s", metrics.ChunksScanned, metrics.BytesScanned, metrics.VerifiedSecretsFound, metrics.UnverifiedSecretsFound, metrics.ScanDuration.String()))
}

func getSlackWebhook(key string, secret string, token string) string {
	cfg := aws.NewConfig()
	cfg.Credentials = credentials.NewStaticCredentials(key, secret, token)
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("ap-northeast-2")},
	)
	if err != nil {
		fmt.Println("Error creating AWS session:", err)
	}

	svc := ssm.New(sess)

	paramName := os.Getenv("SLACK_INFO")
	if paramName == "" {
		paramName = "/trufflehog/slack_url"
	}

	result, err := svc.GetParameter(&ssm.GetParameterInput{
		Name:           &paramName,
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		fmt.Println("Error getting parameter:", err)
	}

	return *result.Parameter.Value
}

func getTeamsWebhook(key string, secret string, token string) string {
	cfg := aws.NewConfig()
	cfg.Credentials = credentials.NewStaticCredentials(key, secret, token)
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("ap-northeast-2")},
	)
	if err != nil {
		fmt.Println("Error creating AWS session:", err)
	}

	svc := ssm.New(sess)

	paramName := os.Getenv("TEAMS_INFO")
	if paramName == "" {
		paramName = "/security/teams_url"
	}

	result, err := svc.GetParameter(&ssm.GetParameterInput{
		Name:           &paramName,
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		fmt.Println("Error getting parameter:", err)
	}

	return *result.Parameter.Value
}

func sendSlackMessage(url string, message string) {
	msg := slackMessage.WebhookMessage{
		Text: message,
	}

	err := slackMessage.PostWebhook(url, &msg)
	if err != nil {
		fmt.Printf("Error sending slack message: %v\n", err)
	}
}

func sendTeamsMessage(url string, title, text string) {
	payload := map[string]interface{}{
		"type": "message",
		"attachments": []map[string]interface{}{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]interface{}{
					"type": "AdaptiveCard",
					"body": []map[string]interface{}{
						{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": title},
						{"type": "TextBlock", "text": text, "wrap": true},
					},
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"version": "1.2",
				},
			},
		},
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("Error sending teams message: %v\n", err)
	}
	defer resp.Body.Close()
}

// logFatalFunc returns a log.Fatal style function. Calling the returned
// function will terminate the program without cleanup.
func logFatalFunc(logger logr.Logger) func(error, string, ...any) {
	return func(err error, message string, keyAndVals ...any) {
		logger.Error(err, message, keyAndVals...)
		if err != nil {
			os.Exit(1)
			return
		}
		os.Exit(0)
	}
}

func commaSeparatedToSlice(s []string) []string {
	var result []string
	for _, items := range s {
		for _, item := range strings.Split(items, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			result = append(result, item)
		}
	}
	return result
}

func printAverageDetectorTime(e *engine.Engine) {
	fmt.Fprintln(os.Stderr, "Average detector time is the measurement of average time spent on each detector when results are returned.")
	for detectorName, duration := range e.GetDetectorsMetrics() {
		fmt.Fprintf(os.Stderr, "%s: %s\n", detectorName, duration)
	}
}

// detectorTypeToSet is a helper function to convert a slice of detector IDs into a set.
func detectorTypeToSet(detectors []config.DetectorID) map[config.DetectorID]struct{} {
	out := make(map[config.DetectorID]struct{}, len(detectors))
	for _, d := range detectors {
		out[d] = struct{}{}
	}
	return out
}

// getWithDetectorID is a helper function to get a value from a map using a
// detector's ID. This function behaves like a normal map lookup, with an extra
// step of checking for the non-specific version of a detector.
func getWithDetectorID[T any](d detectors.Detector, data map[config.DetectorID]T) (T, bool) {
	key := config.GetDetectorID(d)
	// Check if the specific ID is provided.
	if t, ok := data[key]; ok || key.Version == 0 {
		return t, ok
	}
	// Check if the generic type is provided without a version.
	// This means "all" versions of a type.
	key.Version = 0
	t, ok := data[key]
	return t, ok
}

// verifyDetectorsAreVersioner checks all keys in a provided map to verify the
// provided type is actually a Versioner.
func verifyDetectorsAreVersioner[T any](data map[config.DetectorID]T) (error, config.DetectorID) {
	isVersioner := engine.DefaultDetectorTypesImplementing[detectors.Versioner]()
	for id := range data {
		if id.Version == 0 {
			// Version not provided.
			continue
		}
		if _, ok := isVersioner[id.ID]; ok {
			// Version provided for a Versioner detector.
			continue
		}
		// Version provided on a non-Versioner detector.
		return fmt.Errorf("version provided but detector does not have a version"), id
	}
	return nil, config.DetectorID{}
}
