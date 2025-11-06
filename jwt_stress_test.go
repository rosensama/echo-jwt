package jwt

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

// TestConcurrentRequests tests for race conditions under high concurrent load
func TestConcurrentRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	key, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	token, err := generateValidToken()
	if err != nil {
		t.Fatal(err)
	}

	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})
	e.Use(JWT(key))

	// Test with 100 concurrent goroutines making 100 requests each
	numGoroutines := 100
	requestsPerGoroutine := 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan error, numGoroutines*requestsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
				resp := httptest.NewRecorder()
				e.ServeHTTP(resp, req)

				if resp.Code != http.StatusOK {
					errors <- fmt.Errorf("goroutine %d request %d: expected 200, got %d", id, j, resp.Code)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// TestGoroutineLeak tests for goroutine leaks
func TestGoroutineLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	key, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	token, err := generateValidToken()
	if err != nil {
		t.Fatal(err)
	}

	// Get baseline goroutine count
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Run many requests
	for i := 0; i < 1000; i++ {
		e := echo.New()
		e.GET("/", func(c echo.Context) error {
			return c.JSON(http.StatusOK, "ok")
		})
		e.Use(JWT(key))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
	}

	// Force GC and check goroutine count
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()

	// Allow some variance but shouldn't grow significantly
	goroutineDiff := finalGoroutines - initialGoroutines
	if goroutineDiff > 10 {
		t.Errorf("Potential goroutine leak: started with %d, ended with %d (diff: %d)",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}
}

// TestMemoryUsageUnderLoad tests memory usage patterns
func TestMemoryUsageUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	key, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	token, err := generateValidToken()
	if err != nil {
		t.Fatal(err)
	}

	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})
	e.Use(JWT(key))

	// Get initial memory stats
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Run sustained load
	for i := 0; i < 10000; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)

		// Periodically force GC to ensure we're not just accumulating garbage
		if i%1000 == 0 {
			runtime.GC()
		}
	}

	// Final memory stats
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	// Log memory usage for inspection
	t.Logf("Initial HeapAlloc: %d bytes", m1.HeapAlloc)
	t.Logf("Final HeapAlloc: %d bytes", m2.HeapAlloc)
	t.Logf("Total allocations: %d bytes", m2.TotalAlloc-m1.TotalAlloc)
}

// TestConcurrentRefreshTokenRequests tests refresh token handling under concurrent load
func TestConcurrentRefreshTokenRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	key, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	token, err := generateValidToken()
	if err != nil {
		t.Fatal(err)
	}

	e := echo.New()
	e.POST("/auth/refresh", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})
	e.Use(JWTWithConfig(Config{
		Key:             key,
		UseRefreshToken: true,
	}))

	numGoroutines := 50
	requestsPerGoroutine := 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan error, numGoroutines*requestsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				body := fmt.Sprintf(`{"refresh_token": "%s"}`, token)
				req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
				req.Header.Set("Content-Type", "application/json")
				req.Body = http.NoBody

				// Use cookie instead
				cookie := &http.Cookie{
					Name:  "refresh_token",
					Value: string(token),
					Path:  "/",
				}
				req.AddCookie(cookie)

				resp := httptest.NewRecorder()
				e.ServeHTTP(resp, req)

				if resp.Code != http.StatusOK {
					errors <- fmt.Errorf("goroutine %d request %d: expected 200, got %d, body: %s",
						id, j, resp.Code, body)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// TestConcurrentMixedRequests tests mixed request types under load
func TestConcurrentMixedRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	key, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	token, err := generateValidToken()
	if err != nil {
		t.Fatal(err)
	}

	e := echo.New()
	e.GET("/protected", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "protected")
	})
	e.POST("/login", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "login")
	})
	e.GET("/public", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "public")
	})
	e.Use(JWTWithConfig(Config{
		Key: key,
		ExemptRoutes: map[string][]string{
			"/login":  {http.MethodPost},
			"/public": {http.MethodGet},
		},
	}))

	var wg sync.WaitGroup
	numGoroutines := 30

	// Test protected routes with tokens
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				req := httptest.NewRequest(http.MethodGet, "/protected", nil)
				req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
				resp := httptest.NewRecorder()
				e.ServeHTTP(resp, req)
			}
		}()
	}

	// Test exempt routes without tokens
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				req := httptest.NewRequest(http.MethodPost, "/login", nil)
				resp := httptest.NewRecorder()
				e.ServeHTTP(resp, req)
			}
		}()
	}

	// Test public routes
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				req := httptest.NewRequest(http.MethodGet, "/public", nil)
				resp := httptest.NewRecorder()
				e.ServeHTTP(resp, req)
			}
		}()
	}

	wg.Wait()
}
