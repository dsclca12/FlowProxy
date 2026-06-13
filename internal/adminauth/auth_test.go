package adminauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestNewStoreBootstrapAndVerify(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "admin-auth.json")

	store, recoveryCode, err := NewStore(filePath, "admin", "admin")
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	if recoveryCode == "" {
		t.Fatalf("expected bootstrap recovery code")
	}
	if !store.VerifyCredentials("admin", "admin") {
		t.Fatalf("expected credentials to be valid")
	}
	if store.VerifyCredentials("admin", "wrong") {
		t.Fatalf("expected wrong password to fail")
	}
}

func TestUpdateCredentials(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "admin-auth.json")
	store, _, err := NewStore(filePath, "admin", "admin")
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}

	out, err := store.UpdateCredentials("admin", "root", "new-pass-123")
	if err != nil {
		t.Fatalf("update credentials failed: %v", err)
	}
	if out.Username != "root" {
		t.Fatalf("unexpected username: %s", out.Username)
	}
	if !store.VerifyCredentials("root", "new-pass-123") {
		t.Fatalf("expected new credentials to be valid")
	}
}

func TestRecoverCredentialsRotatesRecoveryCode(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "admin-auth.json")
	store, recoveryCode, err := NewStore(filePath, "admin", "admin")
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}

	_, nextCode, err := store.RecoverCredentials(recoveryCode, "rescue", "rescue-pass")
	if err != nil {
		t.Fatalf("recover credentials failed: %v", err)
	}
	if nextCode == "" || nextCode == recoveryCode {
		t.Fatalf("expected rotated recovery code")
	}
	if !store.VerifyCredentials("rescue", "rescue-pass") {
		t.Fatalf("expected recovered credentials to be valid")
	}
	if _, _, err := store.RecoverCredentials(recoveryCode, "rescue2", "rescue-pass-2"); err == nil {
		t.Fatalf("expected old recovery code to be invalid after rotation")
	}
}

func TestManagerLoginAndSessionFlow(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "admin-auth.json")
	store, recoveryCode, err := NewStore(filePath, "admin", "admin")
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	if recoveryCode == "" {
		t.Fatalf("expected bootstrap recovery code")
	}

	manager := NewManager(store)
	mux := http.NewServeMux()
	manager.RegisterRoutes(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := manager.Middleware(mux)

	unauthorizedReq := httptest.NewRequest(http.MethodGet, "/api/sites", nil)
	unauthorizedRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedRec, unauthorizedReq)
	if unauthorizedRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthorized api request, got %d", unauthorizedRec.Code)
	}

	loginBody := map[string]string{"username": "admin", "password": "admin"}
	encodedLogin, _ := json.Marshal(loginBody)
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(encodedLogin))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	handler.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("expected login success, got %d", loginRec.Code)
	}
	cookies := loginRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie")
	}
	if cookies[0].MaxAge != 0 {
		t.Fatalf("expected non-remember login to use session cookie, got MaxAge=%d", cookies[0].MaxAge)
	}

	meReq := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	meReq.AddCookie(cookies[0])
	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusOK {
		t.Fatalf("expected /auth/me success with session, got %d", meRec.Code)
	}
}

func TestManagerLoginRememberMeSetsPersistentCookie(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "admin-auth.json")
	store, _, err := NewStore(filePath, "admin", "admin")
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}

	manager := NewManager(store)
	mux := http.NewServeMux()
	manager.RegisterRoutes(mux)
	handler := manager.Middleware(mux)

	loginBody := map[string]any{
		"username":   "admin",
		"password":   "admin",
		"rememberMe": true,
	}
	encodedLogin, _ := json.Marshal(loginBody)
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(encodedLogin))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	handler.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("expected login success, got %d", loginRec.Code)
	}
	cookies := loginRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie")
	}
	if cookies[0].MaxAge != int(defaultRememberSessionTTL.Seconds()) {
		t.Fatalf("expected remember cookie max age %d, got %d", int(defaultRememberSessionTTL.Seconds()), cookies[0].MaxAge)
	}
}

func TestMiddlewareRejectsCrossSiteUnsafeRequests(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "admin-auth.json")
	store, _, err := NewStore(filePath, "admin", "admin")
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}

	manager := NewManager(store)
	mux := http.NewServeMux()
	manager.RegisterRoutes(mux)
	handler := manager.Middleware(mux)

	loginBody := map[string]string{"username": "admin", "password": "admin"}
	encodedLogin, _ := json.Marshal(loginBody)
	loginReq := httptest.NewRequest(http.MethodPost, "http://admin.example.test/auth/login", bytes.NewReader(encodedLogin))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	handler.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("expected login success, got %d", loginRec.Code)
	}
	cookies := loginRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie")
	}

	changeBody := []byte(`{"currentPassword":"admin","newUsername":"admin","newPassword":"new-pass-123"}`)
	req := httptest.NewRequest(http.MethodPost, "http://admin.example.test/auth/change-password", bytes.NewReader(changeBody))
	req.AddCookie(cookies[0])
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example.test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-site origin, got %d", rec.Code)
	}
}

func TestMiddlewareAllowsSameOriginUnsafeRequests(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "admin-auth.json")
	store, _, err := NewStore(filePath, "admin", "admin")
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}

	manager := NewManager(store)
	mux := http.NewServeMux()
	manager.RegisterRoutes(mux)
	handler := manager.Middleware(mux)

	loginBody := map[string]string{"username": "admin", "password": "admin"}
	encodedLogin, _ := json.Marshal(loginBody)
	loginReq := httptest.NewRequest(http.MethodPost, "http://admin.example.test/auth/login", bytes.NewReader(encodedLogin))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	handler.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("expected login success, got %d", loginRec.Code)
	}
	cookies := loginRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie")
	}

	changeBody := []byte(`{"currentPassword":"admin","newUsername":"admin","newPassword":"new-pass-123"}`)
	req := httptest.NewRequest(http.MethodPost, "http://admin.example.test/auth/change-password", bytes.NewReader(changeBody))
	req.AddCookie(cookies[0])
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://admin.example.test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for same-origin request, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestValidateNewPasswordMinLength(t *testing.T) {
	if err := validateNewPassword("123456789"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("expected weak password error, got %v", err)
	}
	if err := validateNewPassword("1234567890"); err != nil {
		t.Fatalf("expected 10-char password to pass, got %v", err)
	}
}
