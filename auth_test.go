package traefik_auth_middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func setupTestSuccessIamServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, `{"access_token":"test_token","expires_in":3600,"refresh_expires_in":3600,"token_type": "Bearer",		"not_before_policy": 0,"session_state": "test_session_state","scope":"test_scope"}`)
	}))
}

func setupTestAccessDeniedIamServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintln(w, ``)
	}))
}

func setupWorkingPlugin(t *testing.T, ctx context.Context, mock_iam_server *httptest.Server) http.Handler {
	t.Helper()
	cfg := CreateConfig()
	cfg.httpClient = mock_iam_server.Client()
	cfg.IAM = map[string]string{
		"Url":                    mock_iam_server.URL,
		"ClientId":               "my_client_id",
		"UserQueryParamName":     "username_query_param",
		"PasswordQueryParamName": "password_query_param",
	}

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(rw, "It worked")
	})

	handler, err := New(ctx, next, cfg, "sw-auth-plugin")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1 * time.Second)

	return handler
}

func TestFailWhenNoUsernameQueryParam(t *testing.T) {
	mock_iam_server := setupTestSuccessIamServer()
	defer mock_iam_server.Close()

	ctx := context.Background()

	handler := setupWorkingPlugin(t, ctx, mock_iam_server)

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost?password_query_param=password", nil)
	if err != nil {
		t.Fail()
	}

	handler.ServeHTTP(recorder, req)
	response := recorder.Result()
	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status code 400, got  %d", recorder.Code)
	}
}

func TestFailWhenNoPasswordQueryParam(t *testing.T) {
	mock_iam_server := setupTestSuccessIamServer()
	defer mock_iam_server.Close()

	ctx := context.Background()

	handler := setupWorkingPlugin(t, ctx, mock_iam_server)

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost?username_query_param=username", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
	response := recorder.Result()
	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status code 400, got  %d", recorder.Code)
	}
}

func TestFailWithIamReturnUnauthorized(t *testing.T) {
	mock_iam_server := setupTestAccessDeniedIamServer()
	defer mock_iam_server.Close()

	ctx := context.Background()

	handler := setupWorkingPlugin(t, ctx, mock_iam_server)
	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost?username_query_param=username&password_query_param=password", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
	response := recorder.Result()
	
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got %d", recorder.Code)
	}
}

func TestSuccessWithIamReturnOK(t *testing.T) {
	mock_iam_server := setupTestSuccessIamServer()
	defer mock_iam_server.Close()

	ctx := context.Background()

	handler := setupWorkingPlugin(t, ctx, mock_iam_server)
	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost?username_query_param=username&password_query_param=password", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
	response := recorder.Result()
	if response.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", recorder.Code)
	}
}
