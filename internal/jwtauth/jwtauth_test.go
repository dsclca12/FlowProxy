package jwtauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestConfigNormalize(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		HMACSecret:       "my-secret",
		SigningAlgorithm: "HS256",
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("normalize HS256: %v", err)
	}
	if cfg.SigningAlgorithm != "HS256" {
		t.Fatalf("expected HS256, got %s", cfg.SigningAlgorithm)
	}
	if cfg.ExtractFrom != "" && cfg.ExtractFrom != "header" {
		t.Fatalf("expected default extractFrom header, got %s", cfg.ExtractFrom)
	}

	// RSA without JWKS URL should fail
	rsaCfg := Config{
		Enabled:          true,
		SigningAlgorithm: "RS256",
	}
	if err := rsaCfg.Normalize(); err == nil {
		t.Fatalf("expected error for RS256 without jwksUrl")
	}

	// HMAC without secret should fail
	hmacCfg := Config{
		Enabled:          true,
		SigningAlgorithm: "HS256",
	}
	if err := hmacCfg.Normalize(); err == nil {
		t.Fatalf("expected error for HS256 without hmacSecret")
	}
}

func TestTokenFromRequest_Header(t *testing.T) {
	v := &Validator{
		config: Config{
			Enabled:          true,
			ExtractFrom:      "header",
			ExtractName:      "Authorization",
			SigningAlgorithm: "HS256",
			HMACSecret:       "test",
		},
	}
	_ = v.config.Normalize()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer my-token")
	token, err := v.TokenFromRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "my-token" {
		t.Fatalf("expected my-token, got %s", token)
	}

	// Missing auth header
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := v.TokenFromRequest(req2); err == nil {
		t.Fatalf("expected error for missing header")
	}
}

func TestTokenFromRequest_Cookie(t *testing.T) {
	v := &Validator{
		config: Config{
			Enabled:          true,
			ExtractFrom:      "cookie",
			ExtractName:      "token",
			SigningAlgorithm: "HS256",
			HMACSecret:       "test",
		},
	}
	_ = v.config.Normalize()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: "my-jwt"})
	token, err := v.TokenFromRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "my-jwt" {
		t.Fatalf("expected my-jwt, got %s", token)
	}
}

func TestTokenFromRequest_Query(t *testing.T) {
	v := &Validator{
		config: Config{
			Enabled:          true,
			ExtractFrom:      "query",
			ExtractName:      "token",
			SigningAlgorithm: "HS256",
			HMACSecret:       "test",
		},
	}
	_ = v.config.Normalize()

	req := httptest.NewRequest(http.MethodGet, "/api?token=my-jwt-value", nil)
	token, err := v.TokenFromRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "my-jwt-value" {
		t.Fatalf("expected my-jwt-value, got %s", token)
	}
}

func TestValidator_HMAC(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		ExtractFrom:      "header",
		ExtractName:      "Authorization",
		SigningAlgorithm: "HS256",
		HMACSecret:       "test-secret-key-12345",
		Issuer:           "flowproxy-test",
		Audience:         "test-api",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	v, err := NewValidator(ctx, cfg)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	defer v.Close()

	// Generate a valid token
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   "user-123",
		"iss":   "flowproxy-test",
		"aud":   "test-api",
		"email": "user@example.com",
		"exp":   float64(now.Add(time.Hour).Unix()),
		"iat":   float64(now.Unix()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("test-secret-key-12345"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	result, err := v.Validate(req)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if result == nil {
		t.Fatalf("expected claims")
	}
	if result.Subject != "user-123" {
		t.Fatalf("expected sub user-123, got %s", result.Subject)
	}
	if result.Email != "user@example.com" {
		t.Fatalf("expected email user@example.com, got %s", result.Email)
	}
}

func TestValidator_HMAC_Expired(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		ExtractFrom:      "header",
		ExtractName:      "Authorization",
		SigningAlgorithm: "HS256",
		HMACSecret:       "test-secret-key-12345",
	}

	v, err := NewValidator(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	defer v.Close()

	// Expired token
	claims := jwt.MapClaims{
		"sub": "user-123",
		"exp": float64(time.Now().Add(-time.Hour).Unix()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test-secret-key-12345"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	if _, err := v.Validate(req); err == nil {
		t.Fatalf("expected error for expired token")
	}
}

func TestValidator_HMAC_WrongSecret(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		ExtractFrom:      "header",
		ExtractName:      "Authorization",
		SigningAlgorithm: "HS256",
		HMACSecret:       "correct-secret",
	}

	v, err := NewValidator(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	defer v.Close()

	claims := jwt.MapClaims{
		"sub": "user-123",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Sign with wrong secret
	tokenString, _ := token.SignedString([]byte("wrong-secret"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	if _, err := v.Validate(req); err == nil {
		t.Fatalf("expected error for wrong secret")
	}
}

func TestExtractClaims(t *testing.T) {
	claims := jwt.MapClaims{
		"sub":                "user-123",
		"iss":                "test-issuer",
		"aud":                []interface{}{"api-1", "api-2"},
		"email":              "user@example.com",
		"preferred_username": "john",
		"roles":              []interface{}{"admin", "user"},
		"custom-field":       "custom-value",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c := extractClaims(token)

	if c.Subject != "user-123" {
		t.Fatalf("expected sub user-123, got %s", c.Subject)
	}
	if c.Issuer != "test-issuer" {
		t.Fatalf("expected iss test-issuer, got %s", c.Issuer)
	}
	if len(c.Audience) != 2 || c.Audience[0] != "api-1" {
		t.Fatalf("unexpected audience: %v", c.Audience)
	}
	if c.Email != "user@example.com" {
		t.Fatalf("expected email user@example.com, got %s", c.Email)
	}
	if c.Username != "john" {
		t.Fatalf("expected username john, got %s", c.Username)
	}
	if len(c.Roles) != 2 || c.Roles[0] != "admin" {
		t.Fatalf("unexpected roles: %v", c.Roles)
	}
	if c.All["custom-field"] != "custom-value" {
		t.Fatalf("missing custom field")
	}
}

func TestApplyForwardHeaders(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		ExtractFrom:      "header",
		SigningAlgorithm: "HS256",
		HMACSecret:       "secret",
		ForwardToken:     true,
	}
	v, err := NewValidator(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	defer v.Close()

	claims := &Claims{
		Subject:  "user-123",
		Issuer:   "test",
		Email:    "user@example.com",
		Username: "john",
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	v.ApplyForwardHeaders(req, claims)

	if req.Header.Get("X-JWT-Subject") != "user-123" {
		t.Fatalf("unexpected X-JWT-Subject")
	}
	if req.Header.Get("X-JWT-Email") != "user@example.com" {
		t.Fatalf("unexpected X-JWT-Email")
	}
}

func TestValidator_Disabled(t *testing.T) {
	v := &Validator{config: Config{Enabled: false}}
	result, err := v.Validate(nil)
	if err != nil {
		t.Fatalf("expected nil for disabled validator: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result for disabled validator")
	}
}

func TestBase64RawURLDecode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"dGVzdA", "test"},
		{"dGVzdA==", "test"},
		{"", ""},
	}
	for _, tt := range tests {
		result, err := base64RawURLDecode(tt.input)
		if tt.input == "" {
			if err == nil {
				t.Fatalf("expected error for empty input")
			}
			continue
		}
		if err != nil {
			t.Fatalf("decode %q: %v", tt.input, err)
		}
		if string(result) != tt.expected {
			t.Fatalf("decode %q: expected %q, got %q", tt.input, tt.expected, string(result))
		}
	}
}
