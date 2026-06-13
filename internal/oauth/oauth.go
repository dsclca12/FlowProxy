// Package oauth implements OAuth 2.0 / OIDC authentication for FlowProxy sites.
//
// It provides a middleware that redirects unauthenticated users to an
// OAuth provider for login, creates a session upon successful login,
// and forwards authenticated requests to the upstream.
package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Defaults
const (
	DefaultSessionMaxAge = 24 * time.Hour
	SessionCookieName    = "fp_oauth_session"
	StateCookieName      = "fp_oauth_state"
	stateCookieMaxAge    = 10 * time.Minute
)

// ProviderType defines the type of OAuth provider.
type ProviderType string

const (
	ProviderGoogle  ProviderType = "google"
	ProviderGitHub  ProviderType = "github"
	ProviderGeneric ProviderType = "generic"
	ProviderOIDC    ProviderType = "oidc"
)

// SiteConfig defines OAuth configuration for a single site.
type SiteConfig struct {
	Enabled        bool     `json:"enabled,omitempty"`
	Provider       string   `json:"provider,omitempty"`
	ClientID       string   `json:"clientId,omitempty"`
	ClientSecret   string   `json:"clientSecret,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	AllowedDomains []string `json:"allowedDomains,omitempty"`
	AllowedEmails  []string `json:"allowedEmails,omitempty"`
	CallbackURL    string   `json:"callbackUrl,omitempty"`
}

// GlobalConfig defines global OAuth settings.
type GlobalConfig struct {
	SessionSecret string `json:"sessionSecret,omitempty"`
	SessionMaxAge string `json:"sessionMaxAge,omitempty"`
	BaseURL       string `json:"baseUrl,omitempty"`
}

// Session represents an authenticated user session.
type Session struct {
	UserID    string    `json:"userId"`
	Email     string    `json:"email"`
	Provider  string    `json:"provider"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// SessionManager manages authenticated user sessions.
type SessionManager struct {
	mu           sync.RWMutex
	sessions     map[string]*sessionEntry
	secretKey    []byte
	maxAge       time.Duration
	cookieName   string
	cookieDomain string
}

type sessionEntry struct {
	token   string
	session *Session
}

// NewSessionManager creates a new session manager.
func NewSessionManager(secret string, maxAge time.Duration) *SessionManager {
	key := []byte(secret)
	if len(key) == 0 {
		// Generate a random key if none provided
		k := make([]byte, 32)
		if _, err := rand.Read(k); err == nil {
			key = k
		}
	}
	if maxAge <= 0 {
		maxAge = DefaultSessionMaxAge
	}
	return &SessionManager{
		sessions:   make(map[string]*sessionEntry),
		secretKey:  key,
		maxAge:     maxAge,
		cookieName: SessionCookieName,
	}
}

// generateToken creates a cryptographically random session token.
func (sm *SessionManager) generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// signToken creates an HMAC signature for a token.
func (sm *SessionManager) signToken(token string) string {
	mac := hmac.New(sha256.New, sm.secretKey)
	mac.Write([]byte(token))
	return base64.URLEncoding.EncodeToString(mac.Sum(nil))
}

// CreateSession creates a new session and returns the signed cookie value.
func (sm *SessionManager) CreateSession(userID, email, provider string) (string, error) {
	token, err := sm.generateToken()
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	session := &Session{
		UserID:    userID,
		Email:     email,
		Provider:  provider,
		CreatedAt: now,
		ExpiresAt: now.Add(sm.maxAge),
	}

	sm.mu.Lock()
	sm.sessions[token] = &sessionEntry{
		token:   token,
		session: session,
	}
	sm.mu.Unlock()

	// Return signed cookie value: token.signature
	sig := sm.signToken(token)
	return token + "." + sig, nil
}

// ValidateSession validates a session cookie value and returns the session.
func (sm *SessionManager) ValidateSession(cookieValue string) (*Session, error) {
	parts := strings.SplitN(cookieValue, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid session cookie format")
	}
	token, sig := parts[0], parts[1]

	// Verify signature
	expectedSig := sm.signToken(token)
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return nil, errors.New("invalid session signature")
	}

	sm.mu.RLock()
	entry, ok := sm.sessions[token]
	sm.mu.RUnlock()

	if !ok {
		return nil, errors.New("session not found")
	}

	if time.Now().UTC().After(entry.session.ExpiresAt) {
		sm.DeleteSession(token)
		return nil, errors.New("session expired")
	}

	return entry.session, nil
}

// DeleteSession removes a session by token.
func (sm *SessionManager) DeleteSession(token string) {
	sm.mu.Lock()
	delete(sm.sessions, token)
	sm.mu.Unlock()
}

// SessionFromRequest extracts and validates a session from an HTTP request.
func (sm *SessionManager) SessionFromRequest(req *http.Request) (*Session, error) {
	if req == nil {
		return nil, errors.New("request is nil")
	}
	cookie, err := req.Cookie(sm.cookieName)
	if err != nil {
		return nil, fmt.Errorf("session cookie: %w", err)
	}
	return sm.ValidateSession(cookie.Value)
}

// SetSessionCookie sets the session cookie on the response.
func (sm *SessionManager) SetSessionCookie(w http.ResponseWriter, cookieValue string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sm.cookieName,
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sm.maxAge.Seconds()),
	})
}

// ClearSessionCookie clears the session cookie.
func (sm *SessionManager) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sm.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
	})
}

// GenerateState generates a random state value for CSRF protection.
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SetStateCookie sets the OAuth state cookie for CSRF protection.
func SetStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     StateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(stateCookieMaxAge.Seconds()),
	})
}

// VerifyStateCookie verifies the OAuth state parameter matches the cookie.
func VerifyStateCookie(req *http.Request, state string) error {
	cookie, err := req.Cookie(StateCookieName)
	if err != nil {
		return errors.New("state cookie not found")
	}
	if !hmac.Equal([]byte(cookie.Value), []byte(state)) {
		return errors.New("state mismatch")
	}
	return nil
}

// ClearStateCookie clears the OAuth state cookie.
func ClearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     StateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
	})
}

// marshalJSON is a helper for JSON encoding.
func marshalJSON(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(data)
}
