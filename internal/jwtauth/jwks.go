package jwtauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// JWK represents a single JSON Web Key.
type JWK struct {
	KID string   `json:"kid"`
	KTY string   `json:"kty"`
	ALG string   `json:"alg,omitempty"`
	USE string   `json:"use,omitempty"`
	N   string   `json:"n,omitempty"`   // RSA modulus
	E   string   `json:"e,omitempty"`   // RSA exponent
	Crv string   `json:"crv,omitempty"` // EC curve
	X   string   `json:"x,omitempty"`   // EC x coordinate
	Y   string   `json:"y,omitempty"`   // EC y coordinate
	X5C []string `json:"x5c,omitempty"` // X.509 certificate chain
}

// JWKSResponse represents the JWKS endpoint response.
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWKSClient periodically fetches and caches JWKS keys from an endpoint.
type JWKSClient struct {
	url             string
	refreshInterval time.Duration
	httpClient      *http.Client

	mu        sync.RWMutex
	keysByID  map[string]interface{}
	keysByAlg map[string]interface{} // fallback by algorithm

	stopCh chan struct{}
	doneCh chan struct{}
}

// NewJWKSClient creates a new JWKS client with periodic background refresh.
func NewJWKSClient(ctx context.Context, url string, refreshInterval time.Duration) (*JWKSClient, error) {
	if stringsTrimSpace(url) == "" {
		return nil, errors.New("jwks url is required")
	}
	if refreshInterval <= 0 {
		refreshInterval = DefaultJWKSRefreshInterval
	}

	c := &JWKSClient{
		url:             url,
		refreshInterval: refreshInterval,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		keysByID:  make(map[string]interface{}),
		keysByAlg: make(map[string]interface{}),
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}

	// Initial fetch
	if err := c.refresh(); err != nil {
		return nil, fmt.Errorf("initial jwks fetch from %s failed: %w", url, err)
	}

	// Start background refresh
	go c.loop(ctx)

	return c, nil
}

// Close stops the background refresh loop.
func (c *JWKSClient) Close() {
	if c == nil {
		return
	}
	select {
	case <-c.doneCh:
		return
	default:
	}
	close(c.stopCh)
	<-c.doneCh
}

// GetKey retrieves a key by its Key ID (kid).
func (c *JWKSClient) GetKey(kid string) (interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if key, ok := c.keysByID[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("key %q not found in jwks", kid)
}

func (c *JWKSClient) loop(ctx context.Context) {
	defer close(c.doneCh)

	ticker := time.NewTicker(c.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.refresh(); err != nil {
				// Log but don't fail - continue using last known keys
				// In production, consider using structured logging
				fmt.Printf("jwks refresh from %s failed: %v\n", c.url, err)
			}
		}
	}
}

func (c *JWKSClient) refresh() error {
	req, err := http.NewRequest(http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	var jwks JWKSResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("parse jwks: %w", err)
	}

	newKeysByID := make(map[string]interface{}, len(jwks.Keys))
	newKeysByAlg := make(map[string]interface{}, len(jwks.Keys))

	for _, jwk := range jwks.Keys {
		if jwk.USE != "" && jwk.USE != "sig" {
			continue // Only use signing keys
		}

		key, err := jwk.ParseKey()
		if err != nil {
			fmt.Printf("jwks: skipping key %s: %v\n", jwk.KID, err)
			continue
		}

		if jwk.KID != "" {
			newKeysByID[jwk.KID] = key
		}
		if jwk.ALG != "" {
			newKeysByAlg[jwk.ALG] = key
		}
	}

	c.mu.Lock()
	c.keysByID = newKeysByID
	c.keysByAlg = newKeysByAlg
	c.mu.Unlock()

	return nil
}

// ParseKey parses a JWK entry into a Go crypto public key.
func (j *JWK) ParseKey() (interface{}, error) {
	switch j.KTY {
	case "RSA":
		return j.parseRSAKey()
	case "EC":
		return j.parseECKey()
	default:
		return nil, fmt.Errorf("unsupported key type: %s", j.KTY)
	}
}

func (j *JWK) parseRSAKey() (*rsa.PublicKey, error) {
	nBytes, err := base64RawURLDecode(j.N)
	if err != nil {
		return nil, fmt.Errorf("decode rsa modulus: %w", err)
	}
	eBytes, err := base64RawURLDecode(j.E)
	if err != nil {
		return nil, fmt.Errorf("decode rsa exponent: %w", err)
	}

	key := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}
	return key, nil
}

func (j *JWK) parseECKey() (*ecdsa.PublicKey, error) {
	xBytes, err := base64RawURLDecode(j.X)
	if err != nil {
		return nil, fmt.Errorf("decode ec x: %w", err)
	}
	yBytes, err := base64RawURLDecode(j.Y)
	if err != nil {
		return nil, fmt.Errorf("decode ec y: %w", err)
	}

	var curve elliptic.Curve
	switch j.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported ec curve: %s", j.Crv)
	}

	key := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	return key, nil
}

func base64RawURLDecode(s string) ([]byte, error) {
	s = stringsTrimSpace(s)
	if s == "" {
		return nil, errors.New("empty base64 input")
	}
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// stringsTrimSpace is a helper to avoid importing strings in tests.
func stringsTrimSpace(s string) string {
	if len(s) == 0 {
		return s
	}
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	if start == 0 && end == len(s) {
		return s
	}
	return s[start:end]
}
