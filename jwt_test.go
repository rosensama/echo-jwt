package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
)

// testRSAPrivateKey is generated once at package init for all tests
var testRSAPrivateKey *rsa.PrivateKey

func init() {
	var err error
	testRSAPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate RSA key: %v", err))
	}
}

func TestJWT_Auth_Header(t *testing.T) {
	token, err := generateValidToken(t)
	assert.NoError(t, err)

	testCases := []struct {
		name       string
		header     string
		statusCode int
	}{
		{"valid auth scheme valid token", fmt.Sprintf("Bearer %s", token), http.StatusOK},
		{"valid auth scheme valid token case insensitive", fmt.Sprintf("bEaReR %s", token), http.StatusOK},
		{"valid auth scheme invalid token", "Bearer invalid", http.StatusUnauthorized},
		{"invalid auth scheme valid token", fmt.Sprintf("NotBearer %s", token), http.StatusUnauthorized},
		{"invalid auth scheme invalid token", "NotBearer invalid", http.StatusUnauthorized},
		{"invalid header format", "Bearer", http.StatusUnauthorized},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key := getTestRSAPublicKey()

			e.Use(JWT(key))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(echo.HeaderAuthorization, tc.header)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func TestJWT_Auth_Cookie(t *testing.T) {
	token, err := generateValidToken(t)
	assert.NoError(t, err)

	validCookie := &http.Cookie{
		Name:  "access_token",
		Value: string(token),
		Path:  "/",
	}

	wrongNameCookie := &http.Cookie{
		Name:  "not_access_token",
		Value: string(token),
		Path:  "/",
	}

	invalidTokenCookie := &http.Cookie{
		Name:  "access_token",
		Value: "invalid",
		Path:  "/",
	}

	testCases := []struct {
		name       string
		cookie     *http.Cookie
		statusCode int
	}{
		{"valid cookie", validCookie, http.StatusOK},
		{"wrong cookie name", wrongNameCookie, http.StatusUnauthorized},
		{"invalid token cookie", invalidTokenCookie, http.StatusUnauthorized},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key := getTestRSAPublicKey()

			e.Use(JWT(key))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(tc.cookie)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func TestJWT_ReturnStatus(t *testing.T) {
	token, err := generateValidToken(t)
	assert.NoError(t, err)

	expToken, err := generateExpiredToken(t)
	assert.NoError(t, err)

	nbfToken, err := generateFutureNotBefore(t)
	assert.NoError(t, err)

	iatToken, err := generateInvalidIssuedAt(t)
	assert.NoError(t, err)

	testCases := []struct {
		name       string
		token      []byte
		statusCode int
	}{
		{"valid", token, http.StatusOK},
		{"expired", expToken, http.StatusUnauthorized},
		{"not before in future", nbfToken, http.StatusUnauthorized},
		{"invalid issued at", iatToken, http.StatusUnauthorized},
		{"invalid", []byte("invalid"), http.StatusUnauthorized},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key := getTestRSAPublicKey()

			e.Use(JWT(key))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", tc.token))
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func TestJWTWithConfig_Key_Panic(t *testing.T) {
	e := echo.New()

	assert.Panics(t, func() { e.Use(JWTWithConfig(Config{})) })
}

func TestJWT_DefaultConfig_Isolation(t *testing.T) {
	key := getTestRSAPublicKey()

	e := echo.New()
	e.GET("/injected", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})
	e.Use(JWT(key))

	DefaultConfig.ExemptRoutes["/injected"] = []string{http.MethodGet}
	defer delete(DefaultConfig.ExemptRoutes, "/injected")

	req := httptest.NewRequest(http.MethodGet, "/injected", nil)
	resp := httptest.NewRecorder()
	e.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusUnauthorized, resp.Code,
		"JWT() instance should not see routes added to DefaultConfig after middleware was created")
}

func TestJWTWithConfig_RefreshToken_Routes_Isolation(t *testing.T) {
	originalRoutes := make(map[string][]string)
	for k, v := range DefaultConfig.RefreshToken.Routes {
		originalRoutes[k] = v
	}

	key := getTestRSAPublicKey()

	_ = JWTWithConfig(Config{
		Key:             key,
		UseRefreshToken: true,
		RefreshToken:    &RefreshToken{},
	})

	assert.Equal(t, originalRoutes, DefaultConfig.RefreshToken.Routes,
		"DefaultConfig.RefreshToken.Routes should not be modified by JWTWithConfig()")
}

func TestJWTWithConfig_Skipper(t *testing.T) {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})

	key := getTestRSAPublicKey()

	e.Use(JWTWithConfig(Config{
		Key:     key,
		Skipper: func(c echo.Context) bool { return true },
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp := httptest.NewRecorder()

	e.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
}

func TestJWTWithConfig_RefreshToken_Defaults(t *testing.T) {
	e := echo.New()

	e.POST("/auth/refresh", func(c echo.Context) error {
		return c.String(http.StatusOK, c.Get(DefaultConfig.RefreshToken.ContextKeyEncoded).(string))
	})

	key := getTestRSAPublicKey()

	e.Use(JWTWithConfig(Config{
		Key:             key,
		UseRefreshToken: true,
		RefreshToken:    &RefreshToken{},
	}))

	token, err := generateValidToken(t)
	assert.NoError(t, err)

	b := fmt.Sprintf(`{"refresh_token": "%s"}`, token)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewBuffer([]byte(b)))
	req.Header.Add("Content-Type", echo.MIMEApplicationJSON)
	resp := httptest.NewRecorder()

	e.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, string(token), resp.Body.String())
}

func TestJWTWithConfig_RefreshToken_Cookie(t *testing.T) {
	e := echo.New()

	e.POST("/auth/refresh", func(c echo.Context) error {
		return c.String(http.StatusOK, c.Get(DefaultConfig.RefreshToken.ContextKeyEncoded).(string))
	})

	key := getTestRSAPublicKey()

	e.Use(JWTWithConfig(Config{
		Key:             key,
		UseRefreshToken: true,
		RefreshToken:    &RefreshToken{},
	}))

	token, err := generateValidToken()
	assert.NoError(t, err)

	cookie := &http.Cookie{
		Name:  "refresh_token",
		Value: string(token),
		Path:  "/",
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(cookie)
	resp := httptest.NewRecorder()

	e.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, string(token), resp.Body.String())
}

func TestJWTWithConfig_RefreshToken_ContentTypeWithCharset(t *testing.T) {
	e := echo.New()

	e.POST("/auth/refresh", func(c echo.Context) error {
		return c.String(http.StatusOK, c.Get(DefaultConfig.RefreshToken.ContextKeyEncoded).(string))
	})

	key := getTestRSAPublicKey()

	e.Use(JWTWithConfig(Config{
		Key:             key,
		UseRefreshToken: true,
		RefreshToken:    &RefreshToken{},
	}))

	token, err := generateValidToken()
	assert.NoError(t, err)

	b := fmt.Sprintf(`{"refresh_token": "%s"}`, token)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewBuffer([]byte(b)))
	req.Header.Add("Content-Type", "application/json; charset=utf-8")
	resp := httptest.NewRecorder()

	e.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, string(token), resp.Body.String())
}

func TestJWTWithConfig_RefreshToken_Malformed(t *testing.T) {
	token, err := generateValidToken(t)
	assert.NoError(t, err)

	testCases := []struct {
		name        string
		contentType string
		body        *bytes.Buffer
		statusCode  int
		msg         string
	}{
		{
			"wrong content type",
			"wrong",
			bytes.NewBuffer([]byte(fmt.Sprintf(`{"refresh_token": "%s"}`, token))),
			http.StatusBadRequest,
			ErrRequestMalformed,
		},
		{
			"no body",
			echo.MIMEApplicationJSON,
			&bytes.Buffer{},
			http.StatusBadRequest,
			ErrRequestMalformed,
		},
		{
			"malformed json body",
			echo.MIMEApplicationJSON,
			bytes.NewBuffer([]byte("{]")),
			http.StatusBadRequest,
			ErrRequestMalformed,
		},
		{
			"missing body key",
			echo.MIMEApplicationJSON,
			bytes.NewBuffer([]byte(fmt.Sprintf(`{"wrong": "%s"}`, token))),
			http.StatusUnprocessableEntity,
			ErrBodyMissingKey,
		},
		{
			"refresh token not a string (number)",
			echo.MIMEApplicationJSON,
			bytes.NewBuffer([]byte(`{"refresh_token": 123}`)),
			http.StatusBadRequest,
			"refresh token must be a string",
		},
		{
			"refresh token not a string (boolean)",
			echo.MIMEApplicationJSON,
			bytes.NewBuffer([]byte(`{"refresh_token": true}`)),
			http.StatusBadRequest,
			"refresh token must be a string",
		},
		{
			"refresh token not a string (object)",
			echo.MIMEApplicationJSON,
			bytes.NewBuffer([]byte(`{"refresh_token": {"nested": "value"}}`)),
			http.StatusBadRequest,
			"refresh token must be a string",
		},
		{
			"refresh token not a string (array)",
			echo.MIMEApplicationJSON,
			bytes.NewBuffer([]byte(`{"refresh_token": ["value"]}`)),
			http.StatusBadRequest,
			"refresh token must be a string",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.POST("/auth/refresh", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key := getTestRSAPublicKey()

			e.Use(JWTWithConfig(Config{
				Key:             key,
				UseRefreshToken: true,
				RefreshToken:    &RefreshToken{},
			}))

			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", tc.body)
			req.Header.Add("Content-Type", tc.contentType)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
			assert.Contains(t, resp.Body.String(), tc.msg)
		})
	}
}

func TestJWTWithConfig_RefreshToken_MaxBodyBytes(t *testing.T) {
	token, err := generateValidToken(t)
	assert.NoError(t, err)

	testCases := []struct {
		name         string
		maxBodyBytes int64
		bodySize     int
		statusCode   int
		msg          string
	}{
		{
			"within limit",
			1024,
			500,
			http.StatusOK,
			"",
		},
		{
			"exactly at limit",
			1024,
			1024,
			http.StatusRequestEntityTooLarge,
			"request body too large",
		},
		{
			"exceeds limit",
			1024,
			2048,
			http.StatusRequestEntityTooLarge,
			"request body too large",
		},
		{
			"small limit",
			100,
			200,
			http.StatusRequestEntityTooLarge,
			"request body too large",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.POST("/auth/refresh", func(c echo.Context) error {
				return c.String(http.StatusOK, c.Get(DefaultConfig.RefreshToken.ContextKeyEncoded).(string))
			})

			key, err := loadPrivateKey(t, privateKeyPath)
			assert.NoError(t, err)

			e.Use(JWTWithConfig(Config{
				Key:             key,
				UseRefreshToken: true,
				RefreshToken: &RefreshToken{
					MaxBodyBytes: tc.maxBodyBytes,
				},
			}))

			padding := ""
			if tc.bodySize > len(token)+30 {
				padding = string(make([]byte, tc.bodySize-len(token)-30))
			}
			body := fmt.Sprintf(`{"refresh_token": "%s", "padding": "%s"}`, token, padding)

			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewBuffer([]byte(body)))
			req.Header.Add("Content-Type", echo.MIMEApplicationJSON)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
			if tc.msg != "" {
				assert.Contains(t, resp.Body.String(), tc.msg)
			}
		})
	}
}

func TestJWTWithConfig_AfterParseFunc(t *testing.T) {
	fn := func(echo.Context, jwt.Token, string, TokenSource) *echo.HTTPError { return nil }
	errFn := func(echo.Context, jwt.Token, string, TokenSource) *echo.HTTPError {
		return &echo.HTTPError{Code: http.StatusTeapot}
	}

	testCases := []struct {
		name       string
		fn         func(echo.Context, jwt.Token, string, TokenSource) *echo.HTTPError
		statusCode int
	}{
		{"no error", fn, http.StatusOK},
		{"error", errFn, http.StatusTeapot},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key := getTestRSAPublicKey()

			e.Use(JWTWithConfig(Config{
				Key:            key,
				AfterParseFunc: tc.fn,
			}))

			token, err := generateValidToken(t)
			assert.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func TestJWTWithConfig_CustomParseTokenFunc(t *testing.T) {
	customParseCalled := false
	customParseFunc := func(encodedToken string, options []jwt.ParseOption) (jwt.Token, error) {
		customParseCalled = true
		return jwt.Parse([]byte(encodedToken), options...)
	}

	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})

	key := getTestRSAPublicKey()

	e.Use(JWTWithConfig(Config{
		Key:            key,
		ParseTokenFunc: customParseFunc,
		Options:        []jwt.ParseOption{jwt.WithKey(jwa.RS256(), key), jwt.WithValidate(true)},
	}))

	token, err := generateValidToken()
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
	resp := httptest.NewRecorder()

	e.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.True(t, customParseCalled, "custom ParseTokenFunc should have been called")
}

func TestJWTWithConfig_CustomOptions(t *testing.T) {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		token := c.Get("token").(jwt.Token)
		iss, _ := token.Issuer()
		return c.String(http.StatusOK, iss)
	})

	key := getTestRSAPublicKey()

	e.Use(JWTWithConfig(Config{
		Key: key,
		Options: []jwt.ParseOption{
			jwt.WithKey(jwa.RS256(), key),
			jwt.WithValidate(true),
			jwt.WithIssuer("test"),
		},
	}))

	token, err := generateValidToken()
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
	resp := httptest.NewRecorder()

	e.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "test", resp.Body.String())
}

func TestJWTWithConfig_CustomOptions_InvalidIssuer(t *testing.T) {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})

	key := getTestRSAPublicKey()

	e.Use(JWTWithConfig(Config{
		Key: key,
		Options: []jwt.ParseOption{
			jwt.WithKey(jwa.RS256(), key),
			jwt.WithValidate(true),
			jwt.WithIssuer("wrong-issuer"),
		},
	}))

	token, err := generateValidToken()
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
	resp := httptest.NewRecorder()

	e.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusUnauthorized, resp.Code)
}

func afterParseHeader(_ echo.Context, _ jwt.Token, _ string, src TokenSource) *echo.HTTPError {
	if src.String() == Header.String() {
		return nil
	}

	return &echo.HTTPError{Code: http.StatusInternalServerError}
}

func afterParseCookie(_ echo.Context, _ jwt.Token, _ string, src TokenSource) *echo.HTTPError {
	if src == Cookie {
		return nil
	}

	return &echo.HTTPError{Code: http.StatusInternalServerError}
}

func afterParseBody(_ echo.Context, _ jwt.Token, _ string, src TokenSource) *echo.HTTPError {
	if src == Body {
		return nil
	}

	return &echo.HTTPError{Code: http.StatusInternalServerError}
}

func TestJWTWithConfig_AfterParseFunc_Source(t *testing.T) {
	testCases := []struct {
		name   string
		source TokenSource
		fn     func(echo.Context, jwt.Token, string, TokenSource) *echo.HTTPError
	}{
		{"header source", Header, afterParseHeader},
		{"cookie source", Cookie, afterParseCookie},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key := getTestRSAPublicKey()

			e.Use(JWTWithConfig(Config{
				Key:            key,
				AfterParseFunc: tc.fn,
			}))

			token, err := generateValidToken(t)
			assert.NoError(t, err)

			cookie := &http.Cookie{
				Name:  "access_token",
				Value: string(token),
				Path:  "/",
			}

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.source == Header {
				req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
			} else {
				req.AddCookie(cookie)
			}
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, http.StatusOK, resp.Code)
		})
	}
}

func TestJWTWithConfig_RefreshToken_Source(t *testing.T) {
	testCases := []struct {
		name   string
		source TokenSource
		fn     func(echo.Context, jwt.Token, string, TokenSource) *echo.HTTPError
	}{
		{"body source", Body, afterParseBody},
		{"cookie source", Cookie, afterParseCookie},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.POST("/auth/refresh", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key := getTestRSAPublicKey()

			e.Use(JWTWithConfig(Config{
				Key:             key,
				UseRefreshToken: true,
				RefreshToken:    &RefreshToken{},
				AfterParseFunc:  tc.fn,
			}))

			token, err := generateValidToken()
			assert.NoError(t, err)

			var req *http.Request
			if tc.source == Body {
				body := fmt.Sprintf(`{"refresh_token": "%s"}`, token)
				req = httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewBuffer([]byte(body)))
				req.Header.Add("Content-Type", echo.MIMEApplicationJSON)
			} else {
				req = httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
				cookie := &http.Cookie{
					Name:  "refresh_token",
					Value: string(token),
					Path:  "/",
				}
				req.AddCookie(cookie)
			}
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, http.StatusOK, resp.Code)
		})
	}
}

func TestJWTWithConfig_ExemptMethods(t *testing.T) {
	testCases := []struct {
		name       string
		methods    []string
		statusCode int
	}{
		{"get 200", []string{http.MethodGet}, http.StatusOK},
		{"post 200", []string{http.MethodPost}, http.StatusOK},
		{"put 200", []string{http.MethodPut}, http.StatusOK},
		{"patch 200", []string{http.MethodPatch}, http.StatusOK},
		{"delete 200", []string{http.MethodDelete}, http.StatusOK},
		{"options 200", []string{http.MethodOptions}, http.StatusOK},
		{"get 401", []string{http.MethodPost}, http.StatusUnauthorized},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.Any("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key := getTestRSAPublicKey()

			e.Use(JWTWithConfig(Config{
				ExemptMethods: tc.methods,
				Key:           key,
			}))

			req := httptest.NewRequest(tc.methods[0], "/", nil)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, http.StatusOK, resp.Code)
		})
	}
}

func TestJWTWithConfig_ExemptRoutes_WildcardMethod(t *testing.T) {
	testCases := []struct {
		name   string
		method string
	}{
		{"GET", http.MethodGet},
		{"POST", http.MethodPost},
		{"PUT", http.MethodPut},
		{"DELETE", http.MethodDelete},
		{"PATCH", http.MethodPatch},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.Any("/wildcard", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key := getTestRSAPublicKey()

			e.Use(JWTWithConfig(Config{
				ExemptRoutes: map[string][]string{
					"/wildcard": {"*"},
				},
				Key: key,
			}))

			req := httptest.NewRequest(tc.method, "/wildcard", nil)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, http.StatusOK, resp.Code)
		})
	}
}

func TestJWTWithConfig_ExemptRoutes(t *testing.T) {
	testCases := []struct {
		name       string
		pattern    string
		route      string
		statusCode int
	}{
		{"root", "/", "/", http.StatusOK},
		{"users", "/users", "/users", http.StatusOK},
		{"users_id", "/users/:id", "/users/1", http.StatusOK},
		{"users_books", "/users/:id/books", "/users/1/books", http.StatusOK},
		{"users_books_id", "/users/:id/books/:id", "/users/1/books/1", http.StatusOK},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET(tc.route, func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key := getTestRSAPublicKey()

			e.Use(JWTWithConfig(Config{
				ExemptRoutes: map[string][]string{
					tc.route: {http.MethodGet},
				},
				Key: key,
			}))

			req := httptest.NewRequest(http.MethodGet, tc.route, nil)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, http.StatusOK, resp.Code)
		})
	}
}

func TestJWTWithConfig_OptionalRoutes(t *testing.T) {
	testCases := []struct {
		name       string
		routes     map[string][]string
		statusCode int
	}{
		{"success", map[string][]string{"/": {http.MethodGet}}, http.StatusOK},
		{"fail", map[string][]string{"/": {http.MethodPost}}, http.StatusUnauthorized},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key := getTestRSAPublicKey()

			e.Use(JWTWithConfig(Config{
				OptionalRoutes: tc.routes,
				Key:            key,
			}))

			token, err := generateExpiredToken(t)
			assert.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func TestJWT_Route_Not_Found(t *testing.T) {
	testCases := []struct {
		name       string
		endpoint   string
		method     string
		statusCode int
	}{
		{"wrong path", "/wrong", http.MethodGet, http.StatusNotFound},
		{"wrong method", "/", http.MethodPost, http.StatusMethodNotAllowed},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key := getTestRSAPublicKey()

			e.Use(JWT(key))

			req := httptest.NewRequest(tc.method, tc.endpoint, nil)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func TestJWT_AlgorithmInference(t *testing.T) {
	// Helper to generate key pairs for each algorithm type
	type keyPairGenerator func() (privateKey any, publicKey crypto.PublicKey, err error)

	testCases := []struct {
		name         string
		generateKeys keyPairGenerator
		algorithm    jwa.SignatureAlgorithm
	}{
		{
			name: "RSA",
			generateKeys: func() (any, crypto.PublicKey, error) {
				return getTestRSAPrivateKey(), getTestRSAPublicKey(), nil
			},
			algorithm: jwa.RS256(),
		},
		{
			name: "ECDSA_P256",
			generateKeys: func() (any, crypto.PublicKey, error) {
				priv, pub, err := generateECDSAKeyPair(elliptic.P256())
				return priv, pub, err
			},
			algorithm: jwa.ES256(),
		},
		{
			name: "ECDSA_P384",
			generateKeys: func() (any, crypto.PublicKey, error) {
				priv, pub, err := generateECDSAKeyPair(elliptic.P384())
				return priv, pub, err
			},
			algorithm: jwa.ES384(),
		},
		{
			name: "ECDSA_P521",
			generateKeys: func() (any, crypto.PublicKey, error) {
				priv, pub, err := generateECDSAKeyPair(elliptic.P521())
				return priv, pub, err
			},
			algorithm: jwa.ES512(),
		},
		{
			name: "Ed25519",
			generateKeys: func() (any, crypto.PublicKey, error) {
				priv, pub, err := generateEd25519KeyPair()
				return priv, pub, err
			},
			algorithm: jwa.EdDSA(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, publicKey, err := tc.generateKeys()
			assert.NoError(t, err)

			token, err := generateTokenWithKey(tc.algorithm, privateKey)
			assert.NoError(t, err)

			e := echo.New()
			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			e.Use(JWT(publicKey))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, http.StatusOK, resp.Code)
		})
	}
}

func TestJWTWithConfig_AlgorithmInference(t *testing.T) {
	// Test that JWTWithConfig also infers the algorithm when Options is empty
	privateKey, publicKey, err := generateECDSAKeyPair(elliptic.P256())
	assert.NoError(t, err)

	token, err := generateTokenWithKey(jwa.ES256(), privateKey)
	assert.NoError(t, err)

	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})

	e.Use(JWTWithConfig(Config{
		Key: publicKey,
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
	resp := httptest.NewRecorder()

	e.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
}

func generateValidToken() ([]byte, error) {
	t := time.Now()
	return generateToken(t, t, t.Add(time.Minute*10))
}

func generateExpiredToken(t *testing.T) ([]byte, error) {
	now := time.Now().Add(-time.Minute * 10)
	return generateToken(t, now, now, now)
}

func generateFutureNotBefore(t *testing.T) ([]byte, error) {
	now := time.Now()
	return generateToken(t, now, now.Add(time.Minute*10), now.Add(time.Minute*9))
}

func generateInvalidIssuedAt(t *testing.T) ([]byte, error) {
	now := time.Now()
	return generateToken(t, now.Add(time.Minute*10), now, now)
}

func generateToken(iat time.Time, nbf time.Time, exp time.Time) ([]byte, error) {
	key := getTestRSAPrivateKey()

	builder := jwt.NewBuilder().
		Subject("123").
		Issuer("test").
		IssuedAt(iat).
		NotBefore(nbf).
		Expiration(exp)

	token, err := builder.Build()
	if err != nil {
		return nil, err
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		return nil, err
	}

	return signed, nil
}

func getTestRSAPrivateKey() *rsa.PrivateKey {
	return testRSAPrivateKey
}

func getTestRSAPublicKey() *rsa.PublicKey {
	return &testRSAPrivateKey.PublicKey
}

func generateECDSAKeyPair(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func generateEd25519KeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

func generateTokenWithKey(alg jwa.SignatureAlgorithm, key any) ([]byte, error) {
	t := time.Now()
	builder := jwt.NewBuilder().
		Subject("123").
		Issuer("test").
		IssuedAt(t).
		NotBefore(t).
		Expiration(t.Add(time.Minute * 10))

	token, err := builder.Build()
	if err != nil {
		return nil, err
	}

	signed, err := jwt.Sign(token, jwt.WithKey(alg, key))
	if err != nil {
		return nil, err
	}

	return signed, nil
}
