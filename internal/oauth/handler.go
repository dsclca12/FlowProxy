package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// HandlerConfig holds the dependencies for OAuth HTTP handlers.
type HandlerConfig struct {
	SessionManager  *SessionManager
	SiteConfig      SiteConfig
	Provider        Provider
	OnAuthenticated func(userInfo *UserInfo) // optional callback
}

// CheckAuth is a middleware that verifies OAuth authentication.
// It returns the authenticated user info if valid, or nil if not authenticated.
func CheckAuth(sm *SessionManager, req *http.Request) *UserInfo {
	if sm == nil || req == nil {
		return nil
	}
	session, err := sm.SessionFromRequest(req)
	if err != nil {
		return nil
	}
	return &UserInfo{
		ID:      session.UserID,
		Email:   session.Email,
		Subject: session.UserID,
	}
}

// IsAuthorized checks if the user is authorized based on site config.
func IsAuthorized(user *UserInfo, cfg SiteConfig) bool {
	if user == nil {
		return false
	}

	// Check allowed domains
	if len(cfg.AllowedDomains) > 0 {
		emailDomain := ""
		if idx := strings.LastIndex(user.Email, "@"); idx > 0 {
			emailDomain = strings.ToLower(user.Email[idx+1:])
		}
		authorized := false
		for _, domain := range cfg.AllowedDomains {
			if strings.EqualFold(emailDomain, strings.TrimSpace(domain)) {
				authorized = true
				break
			}
		}
		if !authorized {
			return false
		}
	}

	// Check allowed emails
	if len(cfg.AllowedEmails) > 0 {
		authorized := false
		for _, email := range cfg.AllowedEmails {
			if strings.EqualFold(user.Email, strings.TrimSpace(email)) {
				authorized = true
				break
			}
		}
		if !authorized {
			return false
		}
	}

	return true
}

// AuthMiddleware returns an HTTP middleware that enforces OAuth authentication.
// If the user is not authenticated, they are redirected to the OAuth login page.
// For API requests (Accept: application/json or X-Requested-With: XMLHttpRequest),
// a 401 response is returned instead of a redirect.
func AuthMiddleware(cfg HandlerConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if cfg.SessionManager == nil || cfg.Provider == nil {
				next.ServeHTTP(w, req)
				return
			}

			user := CheckAuth(cfg.SessionManager, req)
			if user != nil && IsAuthorized(user, cfg.SiteConfig) {
				// Set user info headers for upstream
				req.Header.Set("X-OAuth-User", user.ID)
				req.Header.Set("X-OAuth-Email", user.Email)
				if user.Name != "" {
					req.Header.Set("X-OAuth-Name", user.Name)
				}
				next.ServeHTTP(w, req)
				return
			}

			// Not authenticated or not authorized
			isAPI := strings.Contains(req.Header.Get("Accept"), "application/json") ||
				strings.EqualFold(req.Header.Get("X-Requested-With"), "XMLHttpRequest")

			if isAPI {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "oauth authentication required",
				})
				return
			}

			// Redirect to login
			redirectURL := fmt.Sprintf("/oauth/%s/login?redirect=%s", cfg.Provider.Name(), req.URL.RequestURI())
			http.Redirect(w, req, redirectURL, http.StatusTemporaryRedirect)
		})
	}
}

// LoginHandler handles the OAuth login initiation.
func LoginHandler(cfg HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if cfg.Provider == nil {
			http.Error(w, "oauth provider not configured", http.StatusInternalServerError)
			return
		}

		redirectParam := strings.TrimSpace(req.URL.Query().Get("redirect"))
		if redirectParam == "" {
			redirectParam = "/"
		}

		state, err := GenerateState()
		if err != nil {
			http.Error(w, "failed to generate state", http.StatusInternalServerError)
			return
		}

		// Store the redirect URL in the state
		stateWithRedirect := state + ":" + redirectParam

		SetStateCookie(w, stateWithRedirect)
		authURL := cfg.Provider.AuthURL(stateWithRedirect)
		http.Redirect(w, req, authURL, http.StatusFound)
	}
}

// CallbackHandler handles the OAuth provider callback.
func CallbackHandler(cfg HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if cfg.Provider == nil || cfg.SessionManager == nil {
			http.Error(w, "oauth not configured", http.StatusInternalServerError)
			return
		}

		code := strings.TrimSpace(req.URL.Query().Get("code"))
		state := strings.TrimSpace(req.URL.Query().Get("state"))
		errorParam := strings.TrimSpace(req.URL.Query().Get("error"))

		if errorParam != "" {
			http.Error(w, fmt.Sprintf("oauth error: %s", errorParam), http.StatusBadRequest)
			return
		}
		if code == "" || state == "" {
			http.Error(w, "missing code or state", http.StatusBadRequest)
			return
		}

		// Verify state
		if err := VerifyStateCookie(req, state); err != nil {
			http.Error(w, fmt.Sprintf("state verification failed: %v", err), http.StatusForbidden)
			return
		}
		ClearStateCookie(w)

		// Extract redirect URL from state
		redirectURL := "/"
		if parts := strings.SplitN(state, ":", 2); len(parts) == 2 {
			redirectURL = parts[1]
		}

		ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
		defer cancel()

		token, err := cfg.Provider.Exchange(ctx, code)
		if err != nil {
			log.Printf("oauth token exchange failed: %v", err)
			http.Error(w, "token exchange failed", http.StatusInternalServerError)
			return
		}

		userInfo, err := cfg.Provider.UserInfo(ctx, token)
		if err != nil {
			log.Printf("oauth user info fetch failed: %v", err)
			http.Error(w, "user info fetch failed", http.StatusInternalServerError)
			return
		}

		if !IsAuthorized(userInfo, cfg.SiteConfig) {
			http.Error(w, "access denied: unauthorized user", http.StatusForbidden)
			return
		}

		sessionCookie, err := cfg.SessionManager.CreateSession(userInfo.ID, userInfo.Email, cfg.Provider.Name())
		if err != nil {
			log.Printf("oauth session creation failed: %v", err)
			http.Error(w, "session creation failed", http.StatusInternalServerError)
			return
		}

		cfg.SessionManager.SetSessionCookie(w, sessionCookie)

		if cfg.OnAuthenticated != nil {
			cfg.OnAuthenticated(userInfo)
		}

		http.Redirect(w, req, redirectURL, http.StatusFound)
	}
}

// LogoutHandler handles user logout.
func LogoutHandler(sm *SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if sm == nil {
			http.Redirect(w, req, "/", http.StatusFound)
			return
		}

		session, err := sm.SessionFromRequest(req)
		if err == nil && session != nil {
			// Delete session from manager
			// We need the token to delete it - extract from cookie
			if cookie, cookieErr := req.Cookie(SessionCookieName); cookieErr == nil {
				if parts := strings.SplitN(cookie.Value, ".", 2); len(parts) == 2 {
					sm.DeleteSession(parts[0])
				}
			}
		}

		sm.ClearSessionCookie(w)
		redirectURL := strings.TrimSpace(req.URL.Query().Get("redirect"))
		if redirectURL == "" {
			redirectURL = "/"
		}
		http.Redirect(w, req, redirectURL, http.StatusFound)
	}
}

// NewHandler creates an HTTP mux for OAuth endpoints.
func NewHandler(cfg HandlerConfig) http.Handler {
	mux := http.NewServeMux()
	providerName := cfg.Provider.Name()

	mux.HandleFunc(fmt.Sprintf("/oauth/%s/login", providerName), LoginHandler(cfg))
	mux.HandleFunc(fmt.Sprintf("/oauth/%s/callback", providerName), CallbackHandler(cfg))
	mux.HandleFunc("/oauth/logout", LogoutHandler(cfg.SessionManager))

	return mux
}

// Ensure http.Handler interface is satisfied.
var _ http.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})

// ErrNotAuthenticated is returned when no valid session is found.
var ErrNotAuthenticated = errors.New("not authenticated")
