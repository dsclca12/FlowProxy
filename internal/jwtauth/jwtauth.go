// Package jwtauth provides JWT validation for FlowProxy sites.
//
// Supports:
//   - Bearer header, Cookie, and Query parameter extraction
//   - HMAC (HS256/HS384/HS512) and RSA/ECDSA (RS256/ES256/ES384) via JWKS
//   - Claims validation (issuer, audience, expiration, not-before)
//   - JWKS endpoint with periodic refresh
//   - Optional token forwarding to upstream services
package jwtauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultJWKSRefreshInterval is the default interval for refreshing JWKS keys.
const DefaultJWKSRefreshInterval = 15 * time.Minute

// ExtractFrom defines where to extract the JWT token from the request.
type ExtractFrom string

const (
	// ExtractFromHeader extracts the JWT from the Authorization: Bearer <token> header.
	ExtractFromHeader ExtractFrom = "header"
	// ExtractFromCookie extracts the JWT from a named cookie.
	ExtractFromCookie ExtractFrom = "cookie"
	// ExtractFromQuery extracts the JWT from a query parameter.
	ExtractFromQuery ExtractFrom = "query"
)

// Config defines JWT authentication for a single site.
type Config struct {
	Enabled          bool   `json:"enabled,omitempty"`
	ExtractFrom      string `json:"extractFrom,omitempty"`
	ExtractName      string `json:"extractName,omitempty"`
	SigningAlgorithm string `json:"signingAlgorithm,omitempty"`
	HMACSecret       string `json:"hmacSecret,omitempty"`
	JWKSURL          string `json:"jwksUrl,omitempty"`
	JWKSRefreshSec   int    `json:"jwksRefreshSec,omitempty"`
	Issuer           string `json:"issuer,omitempty"`
	Audience         string `json:"audience,omitempty"`
	ForwardToken     bool   `json:"forwardToken,omitempty"`

	// headerName is the canonicalized HTTP header name used at runtime.
	headerName string
	// extractFromParsed is the parsed extraction method.
	extractFromParsed ExtractFrom
}

// Normalize validates and normalizes the configuration.
// It returns an error if the configuration is invalid.
func (c *Config) Normalize() error {
	if !c.Enabled {
		return nil
	}

	// Default extraction from header
	from := strings.ToLower(strings.TrimSpace(c.ExtractFrom))
	switch from {
	case "header", "":
		c.extractFromParsed = ExtractFromHeader
	case "cookie":
		c.extractFromParsed = ExtractFromCookie
	case "query":
		c.extractFromParsed = ExtractFromQuery
	default:
		return fmt.Errorf("unsupported jwt extractFrom: %q (supported: header, cookie, query)", c.ExtractFrom)
	}

	// Default extract name
	c.ExtractName = strings.TrimSpace(c.ExtractName)
	if c.ExtractName == "" {
		switch c.extractFromParsed {
		case ExtractFromHeader:
			c.ExtractName = "Authorization"
		case ExtractFromCookie:
			c.ExtractName = "token"
		case ExtractFromQuery:
			c.ExtractName = "token"
		}
	}
	c.headerName = http.CanonicalHeaderKey(c.ExtractName)

	// Default signing algorithm
	algo := strings.ToUpper(strings.TrimSpace(c.SigningAlgorithm))
	if algo == "" {
		algo = "RS256"
	}
	switch algo {
	case "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA":
		c.SigningAlgorithm = algo
	default:
		return fmt.Errorf("unsupported jwt signingAlgorithm: %q", c.SigningAlgorithm)
	}

	// Validate HMAC secret when using HMAC
	isHMAC := strings.HasPrefix(c.SigningAlgorithm, "HS")
	if isHMAC && strings.TrimSpace(c.HMACSecret) == "" {
		return fmt.Errorf("hmacSecret is required for HMAC signing algorithm %s", c.SigningAlgorithm)
	}
	// Validate JWKS URL when using asymmetric algorithms
	if !isHMAC && strings.TrimSpace(c.JWKSURL) == "" {
		return fmt.Errorf("jwksUrl is required for %s signing algorithm", c.SigningAlgorithm)
	}

	c.Issuer = strings.TrimSpace(c.Issuer)
	c.Audience = strings.TrimSpace(c.Audience)
	c.JWKSURL = strings.TrimSpace(c.JWKSURL)
	c.HMACSecret = strings.TrimSpace(c.HMACSecret)

	return nil
}

// Validator validates JWT tokens for a single site configuration.
type Validator struct {
	config Config

	// For HMAC verification
	hmacSecret []byte

	// For asymmetric verification via JWKS
	jwksClient  *JWKSClient
	jwksMu      sync.RWMutex
	jwksKeyFunc jwt.Keyfunc
}

// NewValidator creates a new JWT validator for the given configuration.
func NewValidator(ctx context.Context, cfg Config) (*Validator, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}

	v := &Validator{
		config: cfg,
	}

	// Set up key material
	isHMAC := strings.HasPrefix(cfg.SigningAlgorithm, "HS")
	if isHMAC {
		v.hmacSecret = []byte(cfg.HMACSecret)
	} else if cfg.JWKSURL != "" {
		refreshInterval := time.Duration(cfg.JWKSRefreshSec) * time.Second
		if refreshInterval <= 0 {
			refreshInterval = DefaultJWKSRefreshInterval
		}
		client, err := NewJWKSClient(ctx, cfg.JWKSURL, refreshInterval)
		if err != nil {
			return nil, fmt.Errorf("jwks client: %w", err)
		}
		v.jwksClient = client
		v.jwksKeyFunc = v.jwksKeyFuncImpl
	}

	return v, nil
}

// Close releases resources held by the validator.
func (v *Validator) Close() {
	if v == nil {
		return
	}
	if v.jwksClient != nil {
		v.jwksClient.Close()
	}
}

// jwksKeyFuncImpl returns the key from JWKS that matches the token's Key ID.
func (v *Validator) jwksKeyFuncImpl(token *jwt.Token) (interface{}, error) {
	v.jwksMu.RLock()
	client := v.jwksClient
	v.jwksMu.RUnlock()

	if client == nil {
		return nil, errors.New("jwks client is not initialized")
	}

	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, errors.New("token does not contain kid in header")
	}

	key, err := client.GetKey(kid)
	if err != nil {
		return nil, fmt.Errorf("jwks key lookup: %w", err)
	}

	// Verify the key type matches the expected algorithm
	switch v.config.SigningAlgorithm {
	case "RS256", "RS384", "RS512":
		if _, ok := key.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("expected RSA public key for %s, got %T", v.config.SigningAlgorithm, key)
		}
	case "ES256", "ES384", "ES512":
		if _, ok := key.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("expected ECDSA public key for %s, got %T", v.config.SigningAlgorithm, key)
		}
	}

	return key, nil
}

// keyFunc returns the jwt.Keyfunc for validating tokens.
func (v *Validator) keyFunc(token *jwt.Token) (interface{}, error) {
	// Validate signing algorithm
	if alg, ok := token.Header["alg"].(string); ok && alg != "" {
		if !strings.EqualFold(alg, v.config.SigningAlgorithm) {
			return nil, fmt.Errorf("unexpected signing algorithm: %q (expected %q)", alg, v.config.SigningAlgorithm)
		}
	}

	if v.jwksKeyFunc != nil {
		return v.jwksKeyFunc(token)
	}
	if len(v.hmacSecret) > 0 {
		return v.hmacSecret, nil
	}
	return nil, errors.New("no key material available")
}

// TokenFromRequest extracts the JWT token from the request based on the configuration.
func (v *Validator) TokenFromRequest(req *http.Request) (string, error) {
	if req == nil {
		return "", errors.New("request is nil")
	}

	switch v.config.extractFromParsed {
	case ExtractFromHeader:
		auth := strings.TrimSpace(req.Header.Get(v.config.headerName))
		if auth == "" {
			return "", errors.New("missing authorization header")
		}
		if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			return "", errors.New("authorization header does not use Bearer scheme")
		}
		token := strings.TrimSpace(auth[7:])
		if token == "" {
			return "", errors.New("empty bearer token")
		}
		return token, nil

	case ExtractFromCookie:
		cookie, err := req.Cookie(v.config.ExtractName)
		if err != nil {
			return "", fmt.Errorf("cookie %q: %w", v.config.ExtractName, err)
		}
		value := strings.TrimSpace(cookie.Value)
		if value == "" {
			return "", fmt.Errorf("cookie %q is empty", v.config.ExtractName)
		}
		return value, nil

	case ExtractFromQuery:
		value := strings.TrimSpace(req.URL.Query().Get(v.config.ExtractName))
		if value == "" {
			return "", fmt.Errorf("query parameter %q is empty", v.config.ExtractName)
		}
		return value, nil

	default:
		return "", fmt.Errorf("unsupported extraction method: %s", v.config.extractFromParsed)
	}
}

// Claims holds the parsed JWT claims that can be forwarded to upstream services.
type Claims struct {
	Subject  string
	Issuer   string
	Audience []string
	Email    string
	Username string
	Roles    []string
	All      map[string]interface{}
}

// extractClaims extracts known and custom claims from a JWT token.
func extractClaims(token *jwt.Token) *Claims {
	claimsMap := token.Claims.(jwt.MapClaims)

	c := &Claims{
		All: make(map[string]interface{}),
	}

	if sub, ok := claimsMap["sub"].(string); ok {
		c.Subject = sub
	}
	if iss, ok := claimsMap["iss"].(string); ok {
		c.Issuer = iss
	}
	if aud, ok := claimsMap["aud"]; ok {
		switch v := aud.(type) {
		case string:
			c.Audience = []string{v}
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					c.Audience = append(c.Audience, s)
				}
			}
		}
	}
	if email, ok := claimsMap["email"].(string); ok {
		c.Email = email
	}
	if preferredUsername, ok := claimsMap["preferred_username"].(string); ok {
		c.Username = preferredUsername
	} else if name, ok := claimsMap["name"].(string); ok {
		c.Username = name
	}

	// Extract roles from common claim locations
	if roles, ok := claimsMap["roles"].([]interface{}); ok {
		for _, role := range roles {
			if s, ok := role.(string); ok {
				c.Roles = append(c.Roles, s)
			}
		}
	}
	if realmRoles, ok := claimsMap["realm_access"].(map[string]interface{}); ok {
		if roles, ok := realmRoles["roles"].([]interface{}); ok {
			for _, role := range roles {
				if s, ok := role.(string); ok {
					c.Roles = append(c.Roles, s)
				}
			}
		}
	}
	if resourceAccess, ok := claimsMap["resource_access"].(map[string]interface{}); ok {
		for _, resource := range resourceAccess {
			if resMap, ok := resource.(map[string]interface{}); ok {
				if roles, ok := resMap["roles"].([]interface{}); ok {
					for _, role := range roles {
						if s, ok := role.(string); ok {
							c.Roles = append(c.Roles, s)
						}
					}
				}
			}
		}
	}

	// Copy all claims
	for k, v := range claimsMap {
		c.All[k] = v
	}
	// Remove the known ones we already extracted from All for brevity in JSON
	delete(c.All, "sub")
	delete(c.All, "iss")
	delete(c.All, "aud")
	delete(c.All, "exp")
	delete(c.All, "nbf")
	delete(c.All, "iat")

	return c
}

// Validate extracts and validates a JWT token from the request.
// On success, it returns the parsed claims.
// On failure, it returns an error describing why the token is invalid.
func (v *Validator) Validate(req *http.Request) (*Claims, error) {
	if v == nil || !v.config.Enabled {
		return nil, nil
	}

	tokenStr, err := v.TokenFromRequest(req)
	if err != nil {
		return nil, fmt.Errorf("token extraction: %w", err)
	}

	// Set up validation options
	opts := make([]jwt.ParserOption, 0)
	opts = append(opts, jwt.WithValidMethods([]string{v.config.SigningAlgorithm}))
	if v.config.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.config.Issuer))
	}
	if v.config.Audience != "" {
		opts = append(opts, jwt.WithAudience(v.config.Audience))
	}

	parser := jwt.NewParser(opts...)
	token, err := parser.Parse(tokenStr, v.keyFunc)
	if err != nil {
		return nil, fmt.Errorf("token validation: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("token is not valid")
	}

	claims := extractClaims(token)
	return claims, nil
}

// ApplyForwardHeaders sets JWT claims as headers on the outgoing request to the upstream.
// Only called when ForwardToken is true.
func (v *Validator) ApplyForwardHeaders(req *http.Request, claims *Claims) {
	if v == nil || !v.config.ForwardToken || claims == nil || req == nil {
		return
	}

	req.Header.Set("X-JWT-Subject", claims.Subject)
	req.Header.Set("X-JWT-Issuer", claims.Issuer)
	if claims.Email != "" {
		req.Header.Set("X-JWT-Email", claims.Email)
	}
	if claims.Username != "" {
		req.Header.Set("X-JWT-Username", claims.Username)
	}
}

// ApplyForwardToken sets the original JWT token as a header for upstream.
func (v *Validator) ApplyForwardToken(req *http.Request, tokenStr string) {
	if v == nil || !v.config.ForwardToken || req == nil || tokenStr == "" {
		return
	}
	req.Header.Set("X-JWT-Token", tokenStr)
}
