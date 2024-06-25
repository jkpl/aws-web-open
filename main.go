package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"

	"gopkg.in/ini.v1"
)

func main() {
	if err := mainWithErr(); err != nil {
		log.Panic(err)
	}
}

func mainWithErr() error {
	profileNameFromEnv := os.Getenv("AWS_PROFILE")

	profileName := flag.String("profile", profileNameFromEnv, "AWS profile")
	flag.Parse()
	if profileName == nil || *profileName == "" {
		return fmt.Errorf("profile must be specified")
	}

	homeDir := os.Getenv("HOME")
	credentialsPath := path.Join(homeDir, ".aws", "credentials")

	credentialsCfg, err := ini.Load(credentialsPath)
	if err != nil {
		return fmt.Errorf("failed to load credentials file from path %s: %w", credentialsPath, err)
	}

	profile := credentialsCfg.Section(*profileName)
	if profile == nil {
		return fmt.Errorf("credentials not found for profile %s", *profileName)
	}

	sessionCredentials := struct {
		SessionId    string `json:"sessionId"`
		SessionKey   string `json:"sessionKey"`
		SessionToken string `json:"sessionToken"`
	}{
		SessionId:    profile.Key("aws_access_key_id").String(),
		SessionKey:   profile.Key("aws_secret_access_key").String(),
		SessionToken: profile.Key("aws_session_token").String(),
	}
	if sessionCredentials.SessionId == "" {
		return fmt.Errorf("no access key id found")
	}
	if sessionCredentials.SessionKey == "" {
		return fmt.Errorf("no secret access key found")
	}
	if sessionCredentials.SessionToken == "" {
		return fmt.Errorf("no session token found")
	}

	sessionCredentialsBytes, err := json.Marshal(&sessionCredentials)
	if err != nil {
		return fmt.Errorf("failed to marshal session credential: %w", err)
	}
	sessionCredentialsStr := url.QueryEscape(string(sessionCredentialsBytes))

	reqUrl, err := url.Parse(
		fmt.Sprintf(
			"https://signin.aws.amazon.com/federation?Action=getSigninToken&SessionDuration=%d&Session=%s",
			43200, sessionCredentialsStr,
		),
	)
	if err != nil {
		return fmt.Errorf("failed to build request URL: %w", err)
	}
	req := http.Request{
		URL:    reqUrl,
		Method: http.MethodGet,
		Header: http.Header{
			"content-type": []string{"application/json"},
		},
	}

	resp, err := http.DefaultClient.Do(&req)
	if err != nil {
		return fmt.Errorf("getSigninToken failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("getSiginToken request failed with code %d", resp.StatusCode)
	}

	sessionResponseDecoder := json.NewDecoder(resp.Body)
	var sessionResponse struct {
		SigninToken string
	}
	if err := sessionResponseDecoder.Decode(&sessionResponse); err != nil {
		return fmt.Errorf("failed to decode session response: %w", err)
	}

	if _, err := fmt.Printf(
		"https://signin.aws.amazon.com/federation?Action=login&Destination=%s&SigninToken=%s\n",
		url.QueryEscape("https://console.aws.amazon.com/"),
		sessionResponse.SigninToken,
	); err != nil {
		return err
	}

	return nil
}
