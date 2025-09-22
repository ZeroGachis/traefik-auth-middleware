package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	middleware "github.com/ZeroGachis/traefik-auth-middleware" //nolint:depguard
)

func main() {
	// Crée la config avec valeurs par défaut
	config := middleware.CreateConfig()
	config.IAM = map[string]string{
		"ClientId":               "devices",
		"Url":                    "https://auth.smartway-stage.tech/auth/realms/smartway/protocol/openid-connect/token",
		"UserQueryParamName":     "shop_name",
		"PasswordQueryParamName": "api_key",
	}

	// Wrap un handler simple pour tester
	handler, err := middleware.New(
		context.Background(),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			resp := map[string]string{
				"message": "OK - middleware passed",
				"token":   token,
			}

			w.Header().Set("Content-Type", "application/json")

			if err := json.NewEncoder(w).Encode(resp); err != nil {
				http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)

				return
			}
		}),
		config,
		"sw-auth-plugin",
	)
	if err != nil {
		panic(err)
	}

	// Lance un serveur local pour debug
	println("Middleware debug server started on :8080")
	server := &http.Server{
		Addr:         ":8080",
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  10 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		println("Server failed:", err)
	}
}
