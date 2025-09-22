package traefik_auth_middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

type Config struct {
	IAM map[string]string
	httpClient             *http.Client
}

func CreateConfig() *Config {
	return &Config{
		IAM: make(map[string]string),
		httpClient: http.DefaultClient,
	}
}

type Cerbere struct {
	next                   http.Handler
	name                   string
	httpClient             *http.Client
	clientId               string
	iamUrl                 string
	userQueryParamName     string
	passwordQueryParamName string
}

type KeycloakResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.IAM) != 4 {
		return nil, errors.New("IAM Configuration must be defined")
	}

	return &Cerbere{
		next:                   next,
		name:                   name,
		httpClient:             config.httpClient,
		clientId:               config.IAM["ClientId"],
		iamUrl:                 config.IAM["Url"],
		userQueryParamName:     config.IAM["UserQueryParamName"],
		passwordQueryParamName: config.IAM["PasswordQueryParamName"],
	}, nil
}

func (cerbereConfig *Cerbere) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	username, usernamePresent := query[cerbereConfig.userQueryParamName]
	apikey, apikeyPresent := query[cerbereConfig.passwordQueryParamName]

	if !usernamePresent || !apikeyPresent {
		cerbereConfig.logInfo("MalformedQuery for username or apikey")
		http.Error(rw, "MalformedQuery", http.StatusBadRequest)

		return
	}

	authResponse, err := cerbereConfig.httpClient.PostForm(cerbereConfig.iamUrl, //nolint:noctx
		url.Values{
			"grant_type": {"password"},
			"client_id":  {cerbereConfig.clientId},
			"username":   {username[0]},
			"password":   {apikey[0]},
		},
	)
	if err != nil {
		cerbereConfig.logError("Error fetching auth token:", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}
	defer authResponse.Body.Close()
	if authResponse.StatusCode != http.StatusOK {
		cerbereConfig.logInfo(fmt.Sprintf("Fetching auth token failed: %d", authResponse.StatusCode))
		http.Error(rw, "Forbidden", authResponse.StatusCode)
		return
	}
	body, err := io.ReadAll(authResponse.Body)
	if err != nil {
		cerbereConfig.logError("Error reading auth token body:", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	var result KeycloakResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		cerbereConfig.logError("Error unmarshalling auth token body:", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	cerbereConfig.logInfo("Fetching auth token success for shop: " + username[0])
	req.Header.Set("Authorization", "Bearer "+result.AccessToken)
	cerbereConfig.next.ServeHTTP(rw, req)
}

type Log struct {
	Level      string `json:"level"`
	Message    string `json:"message"`
	PluginName string `json:"plugin_name"`
}

func (plugin *Cerbere) logError(message string, err error) {
	plugin.log("ERROR", fmt.Sprint(message, err))
}

func (plugin *Cerbere) logInfo(message string) {
	plugin.log("INFO", message)
}

func (plugin *Cerbere) log(level string, message string) {
	log := Log{
		Level:      level,
		Message:    fmt.Sprint("Traefik-auth-middleware - ", message),
		PluginName: plugin.name,
	}
	jsonlog, err := json.Marshal(log)
	if err != nil {
		os.Stdout.WriteString(fmt.Sprintln("Traefik-auth-middleware - Failed serialize", level, "log as JSON:", message)) //nolint:staticcheck
	} else {
		os.Stdout.WriteString(string(jsonlog) + "\n")
	}
}
