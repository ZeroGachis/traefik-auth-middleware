# Traefik Auth Middleware

This repository contains a Traefik middleware for authentication via Keycloak, with a **local debug server** to test it outside of Traefik.

---

## Structure

```
traefik-auth-middleware/
|── auth_test.go   # Unit tests
├── auth.go        # Middleware code
├── go.mod
└── debug/
    └── main.go    # Local debug server
```

* `auth.go` → middleware used by Traefik.
* `debug/main.go` → minimal HTTP server to test the middleware and view Keycloak responses.

---

## Dev setup

Install tools and dev dependencies

```bash
mise install
mise run install_yaegi
```

### Run tests

```bash
mise run test
```

### Format and lint the code

```bash
mise run format
mise run lint
```

## Running the debug server

1. Run the server:

```bash
go run debug/.
```

2. The server listens on port `8080`.

---

## Testing the middleware

Using `curl`:

```bash
curl "http://localhost:8080?shop_name=test&api_key=secret"
```

### Example response on success:

```json
{
  "message": "OK - middleware passed",
  "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI..."
}
```

If the request is malformed or authentication fails, the middleware returns an appropriate HTTP status code and an error message.

---

## Logs

The middleware outputs JSON logs to standard output:

```json
{
  "level": "INFO",
  "message": "Traefik-auth-middleware - Fetching auth token success for shop: test",
  "plugin_name": "sw-auth-plugin"
}
```

These logs allow you to track:

* The incoming request and its parameters
* The HTTP request to Keycloak
* Authentication success or failure

---

## Notes

* `main.go` is **only used for local debugging**.
* When using Traefik, running this server is not necessary.
* IAM variables must be configured in the Traefik config or via `CreateConfig()` for debugging.

---

## Debugging points

1. Ensure that the **query params** (`shop_name` and `api_key`) are present.
2. Check that the **JSON logs** show the HTTP request to Keycloak and the `status code`.
3. Using the debug server, you can directly see the Keycloak response in the HTTP response.

---

## Complete debug output example

```
Middleware debug server started on :8080
{"level":"INFO","message":"Traefik-auth-middleware - Fetching auth token success for shop: test","plugin_name":"sw-auth-plugin"}
```

HTTP Response:

```json
{
  "message": "OK - middleware passed",
  "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI..."
}
```
