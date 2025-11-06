package jwt

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/labstack/echo/v4"
)

var (
	benchKey   *rsa.PrivateKey
	benchToken []byte
	once       sync.Once
)

func setupBench() {
	once.Do(func() {
		var err error
		benchKey, err = loadPrivateKey(privateKeyPath)
		if err != nil {
			panic(err)
		}
		benchToken, err = generateValidToken()
		if err != nil {
			panic(err)
		}
	})
}

// BenchmarkJWTMiddleware tests the performance and memory allocation of JWT middleware
func BenchmarkJWTMiddleware(b *testing.B) {
	setupBench()

	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})
	e.Use(JWT(benchKey))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", benchToken))
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
	}
}

// BenchmarkJWTMiddlewareParallel tests concurrent access patterns
func BenchmarkJWTMiddlewareParallel(b *testing.B) {
	setupBench()

	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})
	e.Use(JWT(benchKey))

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", benchToken))
			resp := httptest.NewRecorder()
			e.ServeHTTP(resp, req)
		}
	})
}

// BenchmarkJWTMiddlewareCookie tests cookie-based auth performance
func BenchmarkJWTMiddlewareCookie(b *testing.B) {
	setupBench()

	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})
	e.Use(JWT(benchKey))

	cookie := &http.Cookie{
		Name:  "access_token",
		Value: string(benchToken),
		Path:  "/",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(cookie)
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
	}
}

// BenchmarkJWTMiddlewareExemptRoutes tests exempt route checking
func BenchmarkJWTMiddlewareExemptRoutes(b *testing.B) {
	setupBench()

	e := echo.New()
	e.POST("/login", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})
	e.Use(JWT(benchKey))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
	}
}

// BenchmarkParseToken tests token parsing performance
func BenchmarkParseToken(b *testing.B) {
	setupBench()

	config := DefaultConfig
	config.Key = benchKey

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = config.ParseTokenFunc(string(benchToken), config.Options)
	}
}

// BenchmarkTokenValidation tests token validation under load
func BenchmarkTokenValidation(b *testing.B) {
	setupBench()

	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		token := c.Get("token")
		return c.JSON(http.StatusOK, token)
	})
	e.Use(JWT(benchKey))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", benchToken))
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
	}
}
