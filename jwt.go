package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"slices"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

var errTokenParse = errors.New("failed parsing token")

type TokenSource int

const (
	Unset TokenSource = iota
	Cookie
	Header
	Body
)

func (s TokenSource) String() string {
	return [...]string{"unset", "cookie", "header", "body"}[s]
}

type Config struct {
	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper

	// Key defines the public key used to verify tokens.
	// Must be a crypto.PublicKey (e.g., *rsa.PublicKey, *ecdsa.PublicKey).
	// Required.
	Key crypto.PublicKey

	// ExemptRoutes defines routes and methods that don't require tokens.
	// Optional. Defaults to /login [POST].
	ExemptRoutes map[string][]string

	// ExemptMethods defines methods that don't require tokens.
	// Optional. Defaults to [OPTIONS].
	ExemptMethods []string

	// OptionalRoutes defines routes and methods that
	// can optionally require a token.
	// Optional.
	OptionalRoutes map[string][]string

	// ParseTokenFunc defines a function used to decode tokens.
	// Optional.
	ParseTokenFunc func(string, []jwt.ParseOption) (jwt.Token, error)

	// AfterParseFunc defines a function that will run after
	// the ParseTokenFunc has successfully run.
	// Optional.
	AfterParseFunc func(echo.Context, jwt.Token, string, TokenSource) *echo.HTTPError

	// Options defines jwt.ParseOption options for parsing tokens.
	// Optional. Defaults [jwt.WithValidate(true)].
	Options []jwt.ParseOption

	// ContextKey defines the key that will be used to store the token
	// on the echo.Context when the token is successfully parsed.
	// Optional. Defaults to "token".
	ContextKey string

	// CookieKey defines the key that will be used to read the token
	// from an HTTP cookie.
	// Optional. Defaults to "access_token".
	CookieKey string

	// AuthHeader defines the HTTP header that will be used to
	// read the token from.
	// Optional. Defaults to "Authorization".
	AuthHeader string

	// AuthScheme defines the authorization scheme in the AuthHeader.
	// Optional. Defaults to "Bearer".
	AuthScheme string

	// UseRefreshToken controls whether refresh tokens are used or not.
	// Optional. Defaults to false.
	UseRefreshToken bool

	// RefreshToken holds the configuration related to refresh tokens.
	// Optional.
	RefreshToken *RefreshToken
}

type RefreshToken struct {
	// ContextKey defines the key that will be used to store the refresh token
	// on the echo.Context when the token is successfully parsed.
	// Optional. Defaults to "refresh_token".
	ContextKey string

	// ContextKeyEncoded defines the key that will be used to store the encoded
	// refresh token on the echo.Context when the token is successfully parsed.
	// Optional. Defaults to "refresh_token_encoded".
	ContextKeyEncoded string

	// CookieKey defines the key that will be used to read the refresh token
	// from an HTTP cookie.
	// Optional. Defaults to "refresh_token".
	CookieKey string

	// BodyMIMEType defines the expected MIME type of the request body.
	// Returns a 400 Bad Request if the request's Content-Type header does not match.
	// Optional. Defaults to "application/json".
	BodyMIMEType string

	// BodyKey defines the key that will be used to read the refresh token
	// from the request's body.
	// Returns a 422 UnprocessableEntity if the request's body key is missing.
	// Optional. Defaults to "refresh_token".
	BodyKey string

	// Routes defines routes and methods that require a refresh token.
	// Optional. Defaults to /auth/refresh [POST] and /auth/logout [POST].
	Routes map[string][]string
}

var DefaultConfig = Config{
	Skipper:         middleware.DefaultSkipper,
	ExemptRoutes:    map[string][]string{"/login": {http.MethodPost}},
	ExemptMethods:   []string{http.MethodOptions},
	OptionalRoutes:  map[string][]string{},
	ParseTokenFunc:  parseToken,
	Options:         []jwt.ParseOption{jwt.WithValidate(true)},
	ContextKey:      "token",
	CookieKey:       "access_token",
	AuthHeader:      "Authorization",
	AuthScheme:      "Bearer",
	UseRefreshToken: false,
	RefreshToken: &RefreshToken{
		ContextKey:        "refresh_token",
		ContextKeyEncoded: "refresh_token_encoded",
		CookieKey:         "refresh_token",
		BodyMIMEType:      echo.MIMEApplicationJSON,
		BodyKey:           "refresh_token",
		Routes: map[string][]string{
			"/auth/refresh": {http.MethodPost},
			"/auth/logout":  {http.MethodPost},
		},
	},
}

func JWT(key crypto.PublicKey) echo.MiddlewareFunc {
	c := DefaultConfig
	c.ExemptRoutes = maps.Clone(DefaultConfig.ExemptRoutes)
	c.ExemptMethods = slices.Clone(DefaultConfig.ExemptMethods)
	c.Key = key
	alg, err := inferAlgorithm(key)
	if err != nil {
		panic(fmt.Sprintf("unsupported key type: %T", key))
	}
	c.Options = append(slices.Clone(c.Options), jwt.WithKey(alg, key))
	return JWTWithConfig(c)
}

func JWTWithConfig(config Config) echo.MiddlewareFunc {
	if config.Skipper == nil {
		config.Skipper = DefaultConfig.Skipper
	}

	if config.Key == nil {
		panic("key is required")
	}

	if config.ParseTokenFunc == nil {
		config.ParseTokenFunc = DefaultConfig.ParseTokenFunc
	}

	if len(config.Options) < 1 {
		alg, err := inferAlgorithm(config.Key)
		if err != nil {
			panic(fmt.Sprintf("unsupported key type: %T", config.Key))
		}
		config.Options = slices.Clone(DefaultConfig.Options)
		config.Options = append(config.Options, jwt.WithKey(alg, config.Key))
	}

	if config.ContextKey == "" {
		config.ContextKey = DefaultConfig.ContextKey
	}

	if config.CookieKey == "" {
		config.CookieKey = DefaultConfig.CookieKey
	}

	if config.AuthHeader == "" {
		config.AuthHeader = DefaultConfig.AuthHeader
	}

	if config.AuthScheme == "" {
		config.AuthScheme = DefaultConfig.AuthScheme
	}

	if config.RefreshToken == nil {
		config.RefreshToken = DefaultConfig.RefreshToken
	}

	if config.RefreshToken.ContextKey == "" {
		config.RefreshToken.ContextKey = DefaultConfig.RefreshToken.ContextKey
	}

	if config.RefreshToken.ContextKeyEncoded == "" {
		config.RefreshToken.ContextKeyEncoded = DefaultConfig.RefreshToken.ContextKeyEncoded
	}

	if config.RefreshToken.CookieKey == "" {
		config.RefreshToken.CookieKey = DefaultConfig.RefreshToken.CookieKey
	}

	if config.RefreshToken.BodyMIMEType == "" {
		config.RefreshToken.BodyMIMEType = DefaultConfig.RefreshToken.BodyMIMEType
	}

	if config.RefreshToken.BodyKey == "" {
		config.RefreshToken.BodyKey = DefaultConfig.RefreshToken.BodyKey
	}

	if len(config.RefreshToken.Routes) < 1 {
		config.RefreshToken.Routes = maps.Clone(DefaultConfig.RefreshToken.Routes)
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			path := c.Path()
			method := c.Request().Method

			if check(path, method, config.ExemptRoutes) {
				return next(c)
			}

			for _, i := range config.ExemptMethods {
				if i == c.Request().Method {
					return next(c)
				}
			}

			var tokenSource TokenSource
			var encodedToken string
			var refreshRoute bool

			if config.UseRefreshToken && check(path, method, config.RefreshToken.Routes) {
				refreshRoute = true
				encodedToken = encodedTokenFromCookie(c, config.RefreshToken.CookieKey)
				if encodedToken != "" {
					tokenSource = Cookie
				} else {
					mediaType, _, _ := mime.ParseMediaType(c.Request().Header.Get("Content-Type"))
					if mediaType != config.RefreshToken.BodyMIMEType {
						return echo.NewHTTPError(ErrRequestMalformedStatus, ErrRequestMalformed)
					}

					// there's always a body, so we don't
					// need to handle the error.
					data, _ := io.ReadAll(c.Request().Body)

					var m map[string]any
					err := json.Unmarshal(data, &m)
					if err != nil {
						return echo.NewHTTPError(ErrRequestMalformedStatus, ErrRequestMalformed)
					}

					key := config.RefreshToken.BodyKey
					if val, ok := m[key]; !ok {
						return echo.NewHTTPError(ErrBodyMissingKeyStatus, ErrBodyMissingKey)
					} else {
						strVal, ok := val.(string)
						if !ok {
							return echo.NewHTTPError(ErrRequestMalformedStatus, "refresh token must be a string")
						}
						encodedToken = strVal
					}

					c.Request().Body = io.NopCloser(bytes.NewReader(data))
					tokenSource = Body
				}
			} else {
				encodedToken = encodedTokenFromCookie(c, config.CookieKey)
				tokenSource = Cookie
				if encodedToken == "" {
					tokenSource = Header
					header := c.Request().Header.Get(config.AuthHeader)
					if header != "" {
						split := strings.Split(header, " ")
						if strings.ToLower(split[0]) != strings.ToLower(config.AuthScheme) {
							return echo.NewHTTPError(ErrAuthorizationSchemeStatus, ErrAuthorizationScheme)
						}

						if len(split) < 2 {
							return echo.NewHTTPError(ErrAuthorizationHeaderStatus, ErrAuthorizationHeader)
						}

						encodedToken = split[1]
					}
				}
			}

			token, err := config.ParseTokenFunc(encodedToken, config.Options)
			if err != nil {
				if check(path, method, config.OptionalRoutes) {
					return next(c)
				}

				var routeExists, methodMatches bool
				for _, route := range c.Echo().Routes() {
					if path == route.Path {
						if method == route.Method {
							methodMatches = true
						}
						routeExists = true
					}
				}

				if routeExists && !methodMatches {
					return echo.NewHTTPError(ErrMethodNotAllowedStatus, ErrMethodNotAllowed)
				}

				if !routeExists {
					return echo.NewHTTPError(ErrRouteNotFoundStatus, ErrRouteNotFound)
				}

				if !errors.Is(err, errTokenParse) {
					return err
				} else {
					return echo.NewHTTPError(ErrTokenInvalidStatus, ErrTokenInvalid)
				}
			}

			if !refreshRoute {
				c.Set(config.ContextKey, token)
			} else {
				c.Set(config.RefreshToken.ContextKey, token)
				c.Set(config.RefreshToken.ContextKeyEncoded, encodedToken)
			}

			if config.AfterParseFunc != nil {
				err := config.AfterParseFunc(c, token, encodedToken, tokenSource)
				if err != nil {
					return err
				}
			}

			return next(c)
		}
	}
}

func encodedTokenFromCookie(c echo.Context, key string) string {
	var encodedToken string

	cookie, err := c.Request().Cookie(key)
	if err == nil {
		encodedToken = cookie.Value
	}

	return encodedToken
}

func parseToken(encodedToken string, options []jwt.ParseOption) (jwt.Token, error) {
	token, err := jwt.Parse([]byte(encodedToken), options...)
	if err != nil {
		if errors.Is(err, jwt.TokenExpiredError()) {
			return nil, echo.NewHTTPError(ErrTokenExpiredStatus, ErrTokenExpired)
		}

		if errors.Is(err, jwt.InvalidIssuedAtError()) {
			return nil, echo.NewHTTPError(ErrTokenInvalidIssuedAtStatus, ErrTokenInvalidIssuedAt)
		}

		if errors.Is(err, jwt.TokenNotYetValidError()) {
			return nil, echo.NewHTTPError(ErrTokenNotYetValidStatus, ErrTokenNotYetValid)
		}

		return nil, errTokenParse
	}

	return token, nil
}

func check(path string, method string, m map[string][]string) bool {
	for k, v := range m {
		if k == path {
			for _, i := range v {
				if "*" == i || method == i {
					return true
				}
			}
		}
	}
	return false
}

// inferAlgorithm determines the appropriate JWA signature algorithm
// based on the public key type.
func inferAlgorithm(key crypto.PublicKey) (jwa.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return jwa.RS256(), nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return jwa.ES256(), nil
		case elliptic.P384():
			return jwa.ES384(), nil
		case elliptic.P521():
			return jwa.ES512(), nil
		default:
			return jwa.EmptySignatureAlgorithm(), fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		return jwa.EdDSA(), nil
	default:
		return jwa.EmptySignatureAlgorithm(), fmt.Errorf("unsupported key type: %T", key)
	}
}
