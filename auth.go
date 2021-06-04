package traefik_auth_middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

type Config struct {
	IAM map[string]string
}

func CreateConfig() *Config {
	return &Config{
		IAM: make(map[string]string),
	}
}

type Cerbere struct {
	next                   http.Handler
	name                   string
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
		return nil, fmt.Errorf("IAM Configuration must be defined")
	}

	return &Cerbere{
		next:                   next,
		name:                   name,
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
		http.Error(rw, "MalformedQuery", http.StatusBadRequest)
		return
	}

	authResponse, err := http.PostForm(cerbereConfig.iamUrl,
		url.Values{
			"grant_type": {"password"},
			"client_id":  {cerbereConfig.clientId},
			"username":   {username[0]},
			"password":   {apikey[0]},
		})

	if err == nil {
		if authResponse.StatusCode != http.StatusOK {
			http.Error(rw, "Forbidden", http.StatusUnauthorized)
			return
		}
		body, err := ioutil.ReadAll(authResponse.Body)
		if err == nil {
			var result KeycloakResponse
			err := json.Unmarshal(body, &result)
			if err == nil {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", result.AccessToken))
				cerbereConfig.next.ServeHTTP(rw, req)
			} else {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}
