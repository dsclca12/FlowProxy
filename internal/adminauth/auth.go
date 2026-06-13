package adminauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	defaultUsername           = "admin"
	defaultPassword           = "admin"
	minPasswordLength         = 10
	defaultSessionTTL         = 24 * time.Hour
	defaultRememberSessionTTL = 30 * 24 * time.Hour
	defaultSessionCookieName  = "flowproxy_session"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrWeakPassword       = fmt.Errorf("new password must be at least %d characters", minPasswordLength)
	ErrInvalidRecovery    = errors.New("invalid recovery code")
)

type persistedAccount struct {
	Username         string    `json:"username"`
	PasswordHash     string    `json:"passwordHash"`
	RecoveryCodeHash string    `json:"recoveryCodeHash"`
	RecoveryHint     string    `json:"recoveryHint"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type AccountPublic struct {
	Username     string    `json:"username"`
	RecoveryHint string    `json:"recoveryHint"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type Store struct {
	mu       sync.RWMutex
	filePath string
	value    persistedAccount
}

type session struct {
	Username  string
	ExpiresAt time.Time
	TTL       time.Duration
}

type Manager struct {
	store       *Store
	cookieName  string
	ttl         time.Duration
	rememberTTL time.Duration

	mu       sync.Mutex
	sessions map[string]session
}

func NewStore(filePath string, bootstrapUsername string, bootstrapPassword string) (*Store, string, error) {
	store := &Store{filePath: filePath}
	if err := store.load(); err != nil {
		return nil, "", err
	}

	user := strings.TrimSpace(bootstrapUsername)
	if user == "" {
		user = defaultUsername
	}
	pass := strings.TrimSpace(bootstrapPassword)
	if pass == "" {
		pass = defaultPassword
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	changed := false
	recoveryPlain := ""
	if strings.TrimSpace(store.value.Username) == "" {
		store.value.Username = user
		changed = true
	}
	if strings.TrimSpace(store.value.PasswordHash) == "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err != nil {
			return nil, "", err
		}
		store.value.PasswordHash = string(hash)
		changed = true
	}
	if strings.TrimSpace(store.value.RecoveryCodeHash) == "" {
		var err error
		recoveryPlain, store.value.RecoveryHint, store.value.RecoveryCodeHash, err = generateRecoverySecret()
		if err != nil {
			return nil, "", err
		}
		changed = true
	}
	if store.value.UpdatedAt.IsZero() {
		store.value.UpdatedAt = time.Now().UTC()
		changed = true
	}

	if changed {
		if err := store.saveLocked(); err != nil {
			return nil, "", err
		}
	}

	return store, recoveryPlain, nil
}

func (s *Store) Snapshot() AccountPublic {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return AccountPublic{
		Username:     s.value.Username,
		RecoveryHint: s.value.RecoveryHint,
		UpdatedAt:    s.value.UpdatedAt,
	}
}

func (s *Store) VerifyCredentials(username string, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user := strings.TrimSpace(username)
	if subtle.ConstantTimeCompare([]byte(user), []byte(s.value.Username)) != 1 {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(s.value.PasswordHash), []byte(password)) == nil
}

func (s *Store) UpdateCredentials(currentPassword string, newUsername string, newPassword string) (AccountPublic, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if bcrypt.CompareHashAndPassword([]byte(s.value.PasswordHash), []byte(currentPassword)) != nil {
		return AccountPublic{}, ErrInvalidCredentials
	}

	nextUsername := strings.TrimSpace(newUsername)
	if nextUsername == "" {
		nextUsername = s.value.Username
	}
	if err := validateNewPassword(newPassword); err != nil {
		return AccountPublic{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return AccountPublic{}, err
	}

	s.value.Username = nextUsername
	s.value.PasswordHash = string(hash)
	s.value.UpdatedAt = time.Now().UTC()
	if err := s.saveLocked(); err != nil {
		return AccountPublic{}, err
	}

	return AccountPublic{
		Username:     s.value.Username,
		RecoveryHint: s.value.RecoveryHint,
		UpdatedAt:    s.value.UpdatedAt,
	}, nil
}

func (s *Store) ResetCredentialsByCLI(newUsername string, newPassword string) (AccountPublic, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nextUsername := strings.TrimSpace(newUsername)
	if nextUsername == "" {
		return AccountPublic{}, "", errors.New("new username is required")
	}
	if err := validateNewPassword(newPassword); err != nil {
		return AccountPublic{}, "", err
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return AccountPublic{}, "", err
	}
	nextCode, hint, recoveryHash, err := generateRecoverySecret()
	if err != nil {
		return AccountPublic{}, "", err
	}

	s.value.Username = nextUsername
	s.value.PasswordHash = string(passwordHash)
	s.value.RecoveryHint = hint
	s.value.RecoveryCodeHash = recoveryHash
	s.value.UpdatedAt = time.Now().UTC()
	if err := s.saveLocked(); err != nil {
		return AccountPublic{}, "", err
	}

	return AccountPublic{
		Username:     s.value.Username,
		RecoveryHint: s.value.RecoveryHint,
		UpdatedAt:    s.value.UpdatedAt,
	}, nextCode, nil
}

func (s *Store) RecoverCredentials(recoveryCode string, newUsername string, newPassword string) (AccountPublic, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !matchesRecoveryHash(s.value.RecoveryCodeHash, recoveryCode) {
		return AccountPublic{}, "", ErrInvalidRecovery
	}

	nextUsername := strings.TrimSpace(newUsername)
	if nextUsername == "" {
		return AccountPublic{}, "", errors.New("new username is required")
	}
	if err := validateNewPassword(newPassword); err != nil {
		return AccountPublic{}, "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return AccountPublic{}, "", err
	}

	nextCode, hint, recoveryHash, err := generateRecoverySecret()
	if err != nil {
		return AccountPublic{}, "", err
	}

	s.value.Username = nextUsername
	s.value.PasswordHash = string(hash)
	s.value.RecoveryHint = hint
	s.value.RecoveryCodeHash = recoveryHash
	s.value.UpdatedAt = time.Now().UTC()
	if err := s.saveLocked(); err != nil {
		return AccountPublic{}, "", err
	}

	return AccountPublic{
		Username:     s.value.Username,
		RecoveryHint: s.value.RecoveryHint,
		UpdatedAt:    s.value.UpdatedAt,
	}, nextCode, nil
}

func (s *Store) RotateRecoveryCode() (AccountPublic, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nextCode, hint, recoveryHash, err := generateRecoverySecret()
	if err != nil {
		return AccountPublic{}, "", err
	}
	s.value.RecoveryHint = hint
	s.value.RecoveryCodeHash = recoveryHash
	s.value.UpdatedAt = time.Now().UTC()
	if err := s.saveLocked(); err != nil {
		return AccountPublic{}, "", err
	}
	return AccountPublic{
		Username:     s.value.Username,
		RecoveryHint: s.value.RecoveryHint,
		UpdatedAt:    s.value.UpdatedAt,
	}, nextCode, nil
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(s.filePath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}

	var value persistedAccount
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	value.Username = strings.TrimSpace(value.Username)
	value.PasswordHash = strings.TrimSpace(value.PasswordHash)
	value.RecoveryCodeHash = strings.TrimSpace(value.RecoveryCodeHash)
	value.RecoveryHint = strings.TrimSpace(value.RecoveryHint)
	if !value.UpdatedAt.IsZero() {
		value.UpdatedAt = value.UpdatedAt.UTC()
	}
	s.value = value
	return nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, data, 0o600)
}

func NewManager(store *Store) *Manager {
	return &Manager{
		store:       store,
		cookieName:  defaultSessionCookieName,
		ttl:         defaultSessionTTL,
		rememberTTL: defaultRememberSessionTTL,
		sessions:    map[string]session{},
	}
}

func (m *Manager) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/auth/login", m.handleLogin)
	mux.HandleFunc("/auth/logout", m.handleLogout)
	mux.HandleFunc("/auth/session", m.handleSession)
	mux.HandleFunc("/auth/me", m.handleMe)
	mux.HandleFunc("/auth/change-password", m.handleChangePassword)
}

func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := req.URL.Path
		if isPublicPath(path) {
			if (path == "/login" || path == "/login/" || path == "/login.html") && m.IsAuthenticated(req) {
				http.Redirect(w, req, "/", http.StatusFound)
				return
			}
			next.ServeHTTP(w, req)
			return
		}

		if m.IsAuthenticated(req) {
			if err := validateSameOriginRequest(req); err != nil {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
				return
			}
			next.ServeHTTP(w, req)
			return
		}

		if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/auth/") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}

		http.Redirect(w, req, "/login", http.StatusFound)
	})
}

func (m *Manager) IsAuthenticated(req *http.Request) bool {
	_, ok := m.currentUsername(req)
	return ok
}

func (m *Manager) handleLogin(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var input struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		RememberMe bool   `json:"rememberMe"`
	}
	if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if !m.store.VerifyCredentials(input.Username, input.Password) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": ErrInvalidCredentials.Error()})
		return
	}

	sessionTTL := m.ttl
	if input.RememberMe {
		sessionTTL = m.rememberTTL
	}
	token, err := m.newSession(strings.TrimSpace(input.Username), sessionTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	m.setSessionCookie(w, req, token, input.RememberMe, sessionTTL)
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"account":       m.store.Snapshot(),
	})
}

func (m *Manager) handleLogout(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if cookie, err := req.Cookie(m.cookieName); err == nil {
		m.deleteSession(cookie.Value)
	}
	m.clearSessionCookie(w, req)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (m *Manager) handleMe(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	username, ok := m.currentUsername(req)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"username":      username,
		"account":       m.store.Snapshot(),
	})
}

func (m *Manager) handleSession(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	username, ok := m.currentUsername(req)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"username":      username,
	})
}

func (m *Manager) handleChangePassword(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, ok := m.currentUsername(req); !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	var input struct {
		CurrentPassword string `json:"currentPassword"`
		NewUsername     string `json:"newUsername"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	account, err := m.store.UpdateCredentials(input.CurrentPassword, input.NewUsername, input.NewPassword)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrInvalidCredentials) {
			status = http.StatusUnauthorized
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	m.invalidateAllSessions()
	token, err := m.newSession(account.Username, m.ttl)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	m.setSessionCookie(w, req, token, false, m.ttl)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"account": account,
	})
}

func (m *Manager) currentUsername(req *http.Request) (string, bool) {
	cookie, err := req.Cookie(m.cookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return "", false
	}

	now := time.Now().UTC()
	token := cookie.Value
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[token]
	if !ok {
		return "", false
	}
	if now.After(sess.ExpiresAt) {
		delete(m.sessions, token)
		return "", false
	}
	ttl := sess.TTL
	if ttl <= 0 {
		ttl = m.ttl
	}
	sess.ExpiresAt = now.Add(ttl)
	m.sessions[token] = sess
	return sess.Username, true
}

func (m *Manager) newSession(username string, ttl time.Duration) (string, error) {
	token, err := randomHex(32)
	if err != nil {
		return "", err
	}
	if ttl <= 0 {
		ttl = m.ttl
	}
	now := time.Now().UTC()
	m.mu.Lock()
	m.sessions[token] = session{
		Username:  username,
		ExpiresAt: now.Add(ttl),
		TTL:       ttl,
	}
	m.mu.Unlock()
	return token, nil
}

func (m *Manager) deleteSession(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
}

func (m *Manager) invalidateAllSessions() {
	m.mu.Lock()
	m.sessions = map[string]session{}
	m.mu.Unlock()
}

func (m *Manager) setSessionCookie(w http.ResponseWriter, req *http.Request, token string, persistent bool, ttl time.Duration) {
	secure := req.TLS != nil
	cookie := &http.Cookie{
		Name:     m.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
	if persistent {
		if ttl <= 0 {
			ttl = m.rememberTTL
		}
		cookie.MaxAge = int(ttl.Seconds())
	}
	http.SetCookie(w, cookie)
}

func (m *Manager) clearSessionCookie(w http.ResponseWriter, req *http.Request) {
	secure := req.TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func isPublicPath(path string) bool {
	if path == "/login" || path == "/login/" || path == "/login.html" {
		return true
	}
	if path == "/auth/login" {
		return true
	}
	if path == "/auth/session" {
		return true
	}
	return false
}

func validateNewPassword(password string) error {
	if len([]rune(strings.TrimSpace(password))) < minPasswordLength {
		return ErrWeakPassword
	}
	return nil
}

func generateRecoverySecret() (string, string, string, error) {
	raw, err := randomHex(10)
	if err != nil {
		return "", "", "", err
	}
	code := formatRecoveryCode(strings.ToUpper(raw))
	normalized := normalizeRecoveryCode(code)
	hash := sha256.Sum256([]byte(normalized))
	return code, recoveryHintFromCode(code), hex.EncodeToString(hash[:]), nil
}

func matchesRecoveryHash(storedHash string, code string) bool {
	stored, err := hex.DecodeString(strings.TrimSpace(storedHash))
	if err != nil || len(stored) != sha256.Size {
		return false
	}
	normalized := normalizeRecoveryCode(code)
	if normalized == "" {
		return false
	}
	sum := sha256.Sum256([]byte(normalized))
	return subtle.ConstantTimeCompare(stored, sum[:]) == 1
}

func normalizeRecoveryCode(code string) string {
	value := strings.ToUpper(strings.TrimSpace(code))
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, " ", "")
	return value
}

func formatRecoveryCode(raw string) string {
	if raw == "" {
		return ""
	}
	parts := make([]string, 0, (len(raw)+3)/4)
	for i := 0; i < len(raw); i += 4 {
		end := i + 4
		if end > len(raw) {
			end = len(raw)
		}
		parts = append(parts, raw[i:end])
	}
	return strings.Join(parts, "-")
}

func recoveryHintFromCode(code string) string {
	normalized := normalizeRecoveryCode(code)
	if normalized == "" {
		return "configured"
	}
	tail := normalized
	if len(tail) > 4 {
		tail = tail[len(tail)-4:]
	}
	return fmt.Sprintf("ends with %s", tail)
}

func validateSameOriginRequest(req *http.Request) error {
	if req == nil || isSafeMethod(req.Method) {
		return nil
	}

	if fetchSite := strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Site"))); fetchSite == "cross-site" {
		return errors.New("cross-site requests are not allowed")
	}

	if origin := strings.TrimSpace(req.Header.Get("Origin")); origin != "" {
		if !sameOriginHost(origin, req.Host) {
			return errors.New("request origin is not allowed")
		}
		return nil
	}

	if referer := strings.TrimSpace(req.Header.Get("Referer")); referer != "" && !sameOriginHost(referer, req.Host) {
		return errors.New("request referer is not allowed")
	}

	return nil
}

func isSafeMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func sameOriginHost(rawURL string, requestHost string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return false
	}
	leftHost, leftPort := splitHostPortLoose(parsed.Host)
	rightHost, rightPort := splitHostPortLoose(requestHost)
	if leftHost == "" || rightHost == "" {
		return false
	}
	if !strings.EqualFold(leftHost, rightHost) {
		return false
	}
	return leftPort == rightPort
}

func splitHostPortLoose(value string) (string, string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", ""
	}

	if host, port, err := net.SplitHostPort(trimmed); err == nil {
		return strings.ToLower(host), port
	}

	if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		return strings.ToLower(strings.Trim(trimmed, "[]")), ""
	}

	return strings.ToLower(trimmed), ""
}

func randomHex(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
