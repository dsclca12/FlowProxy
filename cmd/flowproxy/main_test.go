package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flowproxy/internal/adminauth"
	"flowproxy/internal/certmgr"
	"flowproxy/internal/clustersync"
	"flowproxy/internal/config"
	"flowproxy/internal/settings"
)

func TestRedirectToHTTPSHandlerUsesConfiguredPort(t *testing.T) {
	handler := redirectToHTTPSHandler(":8443")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path?q=1", nil)
	req.Host = "example.com:8080"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusMovedPermanently {
		t.Fatalf("expected status 301, got %d", recorder.Code)
	}
	if got, want := recorder.Header().Get("Location"), "https://example.com:8443/path?q=1"; got != want {
		t.Fatalf("unexpected redirect location: got %q want %q", got, want)
	}
}

func TestRedirectToHTTPSHandlerOmitsDefaultPort(t *testing.T) {
	handler := redirectToHTTPSHandler(":443")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path?q=1", nil)
	req.Host = "example.com:8080"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if got, want := recorder.Header().Get("Location"), "https://example.com/path?q=1"; got != want {
		t.Fatalf("unexpected redirect location: got %q want %q", got, want)
	}
}

func TestRedirectToHTTPSHandlerKeepsIPv6Host(t *testing.T) {
	handler := redirectToHTTPSHandler("0.0.0.0:9443")

	req := httptest.NewRequest(http.MethodGet, "http://[2001:db8::1]/v1", nil)
	req.Host = "[2001:db8::1]:8080"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if got, want := recorder.Header().Get("Location"), "https://[2001:db8::1]:9443/v1"; got != want {
		t.Fatalf("unexpected redirect location: got %q want %q", got, want)
	}
}

func TestAddrWithPort(t *testing.T) {
	if got, want := addrWithPort(":9000", 19000), ":19000"; got != want {
		t.Fatalf("unexpected addr: got %q want %q", got, want)
	}
	if got, want := addrWithPort("0.0.0.0:9000", 19000), "0.0.0.0:19000"; got != want {
		t.Fatalf("unexpected addr: got %q want %q", got, want)
	}
	if got, want := addrWithPort("[::1]:9000", 19000), "[::1]:19000"; got != want {
		t.Fatalf("unexpected addr: got %q want %q", got, want)
	}
}

func TestAdminDenied(t *testing.T) {
	allow, err := parseAdminIPRules([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatalf("parse allow failed: %v", err)
	}
	deny, err := parseAdminIPRules([]string{"10.0.0.5"})
	if err != nil {
		t.Fatalf("parse deny failed: %v", err)
	}

	if adminDenied(allow, deny, "10.0.0.8") {
		t.Fatalf("expected allow for 10.0.0.8")
	}
	if !adminDenied(allow, deny, "10.0.1.2") {
		t.Fatalf("expected deny for non-allowlisted ip")
	}
	if !adminDenied(allow, deny, "10.0.0.5") {
		t.Fatalf("expected deny for explicit deny ip")
	}
}

func TestAdminAuthMiddleware(t *testing.T) {
	auth := newAdminAuthController("admin", "secret")
	if auth == nil {
		t.Fatalf("expected auth controller")
	}
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	reqUnauthorized := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	recUnauthorized := httptest.NewRecorder()
	handler.ServeHTTP(recUnauthorized, reqUnauthorized)
	if recUnauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without credentials, got %d", recUnauthorized.Code)
	}

	reqAuthorized := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	reqAuthorized.SetBasicAuth("admin", "secret")
	recAuthorized := httptest.NewRecorder()
	handler.ServeHTTP(recAuthorized, reqAuthorized)
	if recAuthorized.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid credentials, got %d", recAuthorized.Code)
	}
}

func TestValidateAdminSecurity(t *testing.T) {
	baseSettings := settings.Settings{}
	publicCfg := config.Config{AdminAddr: ":9000"}
	loopbackCfg := config.Config{AdminAddr: "127.0.0.1:9000"}

	if err := validateAdminSecurity(publicCfg, baseSettings); err != nil {
		t.Fatalf("expected no error for public admin without auth/allowlist (guard disabled), got %v", err)
	}
	if err := validateAdminSecurity(loopbackCfg, baseSettings); err != nil {
		t.Fatalf("expected no error for loopback admin, got %v", err)
	}
	if err := validateAdminSecurity(config.Config{
		AdminAddr:     ":9000",
		AdminUsername: "admin",
		AdminPassword: "secret",
	}, baseSettings); err != nil {
		t.Fatalf("expected no error for public admin with auth, got %v", err)
	}
	if err := validateAdminSecurity(publicCfg, settings.Settings{
		WebAccess: settings.WebAccess{
			AllowCIDRs: []string{"10.0.0.0/24"},
		},
	}); err != nil {
		t.Fatalf("expected no error for public admin with allowlist, got %v", err)
	}
	if err := validateAdminSecurity(config.Config{
		AdminAddr:     ":9000",
		AdminUsername: "admin",
	}, baseSettings); err == nil {
		t.Fatalf("expected error when only admin username is configured")
	}
}

func TestValidateAdminCredentialStrength(t *testing.T) {
	tmp := t.TempDir()
	authFile := filepath.Join(tmp, "admin-auth.json")
	store, _, err := adminauth.NewStore(authFile, "admin", "admin")
	if err != nil {
		t.Fatalf("new auth store failed: %v", err)
	}

	cfg := config.Config{AdminAddr: ":9000"}
	if err := validateAdminCredentialStrength(cfg, settings.Settings{}, store); err == nil {
		t.Fatalf("expected warning condition for public admin using default password without allowlist")
	}

	if err := validateAdminCredentialStrength(cfg, settings.Settings{
		WebAccess: settings.WebAccess{
			AllowCIDRs: []string{"127.0.0.1/32"},
		},
	}, store); err != nil {
		t.Fatalf("expected allowlist to pass, got %v", err)
	}
	if err := validateAdminCredentialStrength(config.Config{AdminAddr: "127.0.0.1:9000"}, settings.Settings{}, store); err != nil {
		t.Fatalf("expected loopback admin to allow default password, got %v", err)
	}

	if _, _, err := store.ResetCredentialsByCLI("ops", "ops-pass-123"); err != nil {
		t.Fatalf("reset credentials failed: %v", err)
	}
	if err := validateAdminCredentialStrength(cfg, settings.Settings{}, store); err != nil {
		t.Fatalf("expected non-default credentials to pass, got %v", err)
	}
}

func TestRunResetAdminCLI(t *testing.T) {
	tmp := t.TempDir()
	authFile := filepath.Join(tmp, "admin-auth.json")

	if err := runResetAdminCLI([]string{
		"--auth-file", authFile,
		"--username", "ops",
		"--password", "ops-pass-123",
	}); err != nil {
		t.Fatalf("runResetAdminCLI failed: %v", err)
	}

	store, _, err := adminauth.NewStore(authFile, "", "")
	if err != nil {
		t.Fatalf("open auth store failed: %v", err)
	}
	if !store.VerifyCredentials("ops", "ops-pass-123") {
		t.Fatalf("expected reset credentials to be valid")
	}
}

func TestValidateAdminTLSConfig(t *testing.T) {
	if err := validateAdminTLSConfig(config.Config{}); err != nil {
		t.Fatalf("expected empty admin tls config to pass, got %v", err)
	}
	if err := validateAdminTLSConfig(config.Config{
		AdminHTTPSAddr:         ":9443",
		AdminTLSAutoSelfSigned: false,
	}); err == nil {
		t.Fatalf("expected error when admin https enabled without cert and without self-signed")
	}
	if err := validateAdminTLSConfig(config.Config{
		AdminHTTPSAddr:         ":9443",
		AdminTLSCertFile:       "/tmp/a.crt",
		AdminTLSKeyFile:        "/tmp/a.key",
		AdminTLSAutoSelfSigned: false,
	}); err != nil {
		t.Fatalf("expected explicit cert/key config to pass, got %v", err)
	}
	if err := validateAdminTLSConfig(config.Config{
		AdminHTTPSAddr:        ":9443",
		AdminTLSCertificateID: "cert-admin",
	}); err != nil {
		t.Fatalf("expected managed certificate id config to pass, got %v", err)
	}
	if err := validateAdminTLSConfig(config.Config{
		AdminHTTPSAddr:        ":9443",
		AdminTLSCertificateID: "cert-admin",
		AdminTLSCertFile:      "/tmp/a.crt",
		AdminTLSKeyFile:       "/tmp/a.key",
	}); err == nil {
		t.Fatalf("expected conflict error when cert id and cert file are both configured")
	}
}

func TestClusterSyncFailCloseMiddleware(t *testing.T) {
	state := clustersync.NewRuntimeState(clustersync.ModeFollower, settings.ClusterSync{
		CertificateSyncEnabled:       true,
		FailCloseEnabled:             true,
		FailCloseConsecutiveFailures: 1,
		FailCloseStaleAfter:          "5m",
	}, 3*time.Second)
	now := time.Now().UTC()
	state.StartAttempt(now)
	state.MarkFailure("fetch", testErr("boom"), now.Add(time.Second))

	handler := clusterSyncFailCloseMiddleware(state, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header")
	}
}

func TestNextClusterSyncDelay(t *testing.T) {
	if got := nextClusterSyncDelay(3*time.Second, 0, 0.5); got != 3*time.Second {
		t.Fatalf("expected base interval delay, got %v", got)
	}
	if got := nextClusterSyncDelay(3*time.Second, 3, 0.5); got != 12*time.Second {
		t.Fatalf("expected exponential backoff delay, got %v", got)
	}
	if got := nextClusterSyncDelay(10*time.Second, 8, 0.5); got != 60*time.Second {
		t.Fatalf("expected backoff capped by max delay, got %v", got)
	}
	if got := nextClusterSyncDelay(3*time.Second, 0, 0.0); got != 2400*time.Millisecond {
		t.Fatalf("expected negative jitter applied, got %v", got)
	}
	if got := nextClusterSyncDelay(time.Millisecond, 0, 0.5); got != 500*time.Millisecond {
		t.Fatalf("expected minimum delay clamp, got %v", got)
	}
}

func TestBuildHAMetrics(t *testing.T) {
	now := time.Now().UTC()
	metrics := buildHAMetrics(clustersync.RuntimeStatus{
		FailCloseActive:     true,
		ConsecutiveFailures: 3,
		LastSuccessAt:       now,
	}, false, "etcd_lock", "node-a", 7, "node-a", true, 5)
	if !strings.Contains(metrics, "flowproxy_control_writable 0") {
		t.Fatalf("missing control writable metric: %s", metrics)
	}
	if !strings.Contains(metrics, "flowproxy_ha_leader_switch_total 7") {
		t.Fatalf("missing leader switch metric: %s", metrics)
	}
	if !strings.Contains(metrics, "flowproxy_ha_leader_flapping 1") || !strings.Contains(metrics, "flowproxy_ha_leader_recent_events 5") {
		t.Fatalf("missing flapping metrics: %s", metrics)
	}
	if !strings.Contains(metrics, "flowproxy_cluster_sync_fail_close_active 1") {
		t.Fatalf("missing fail-close metric: %s", metrics)
	}
	if !strings.Contains(metrics, "flowproxy_ha_leader_is_local 1") {
		t.Fatalf("missing leader-local metric: %s", metrics)
	}
	if !strings.Contains(metrics, "election_mode=\"etcd_lock\"") {
		t.Fatalf("missing leader info labels: %s", metrics)
	}
}

func TestBuildMirroredCertificatesReusesCachedBundle(t *testing.T) {
	remote := certmgr.Certificate{
		ID:        "cert-a",
		Type:      certmgr.TypeSelfSigned,
		Status:    certmgr.StatusActive,
		Domains:   []string{"Example.COM"},
		UpdatedAt: time.Unix(1700000000, 0).UTC(),
	}
	previous := map[string]clusterSyncCertificateCacheEntry{
		"cert-a": {
			cacheKey:  clusterSyncCertificateCacheKey(remote),
			bundleZIP: []byte("cached-zip"),
		},
	}
	calls := 0
	mirrored, next, digest, err := buildMirroredCertificates(remoteSlice(remote), previous, func(id string) ([]byte, error) {
		calls++
		return nil, fmt.Errorf("unexpected fetch for %s", id)
	})
	if err != nil {
		t.Fatalf("build mirrored failed: %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected 0 fetch calls, got %d", calls)
	}
	if digest == "" {
		t.Fatalf("expected non-empty digest")
	}
	if len(mirrored) != 1 {
		t.Fatalf("expected 1 mirrored cert, got %d", len(mirrored))
	}
	if got := string(mirrored[0].BundleZIP); got != "cached-zip" {
		t.Fatalf("expected cached bundle to be reused, got %q", got)
	}
	if len(next) != 1 || string(next["cert-a"].bundleZIP) != "cached-zip" {
		t.Fatalf("expected next cache to retain cached bundle")
	}
}

func TestBuildMirroredCertificatesFetchesChangedAndUnavailable(t *testing.T) {
	base := certmgr.Certificate{
		ID:        "cert-a",
		Type:      certmgr.TypeSelfSigned,
		Status:    certmgr.StatusActive,
		Domains:   []string{"example.com"},
		UpdatedAt: time.Unix(1700000000, 0).UTC(),
	}
	changed := base
	changed.UpdatedAt = changed.UpdatedAt.Add(time.Minute)
	unavailable := certmgr.Certificate{
		ID:        "cert-b",
		Type:      certmgr.TypeACME,
		Status:    certmgr.StatusPending,
		UpdatedAt: time.Unix(1700000100, 0).UTC(),
	}
	previous := map[string]clusterSyncCertificateCacheEntry{
		"cert-a": {
			cacheKey:  clusterSyncCertificateCacheKey(base),
			bundleZIP: []byte("old-zip"),
		},
	}
	calls := map[string]int{}
	mirrored, next, _, err := buildMirroredCertificates([]certmgr.Certificate{changed, unavailable}, previous, func(id string) ([]byte, error) {
		calls[id]++
		switch id {
		case "cert-a":
			return []byte("new-zip"), nil
		case "cert-b":
			return nil, errors.New("certificate material is not available")
		default:
			return nil, errors.New("unexpected certificate id")
		}
	})
	if err != nil {
		t.Fatalf("build mirrored failed: %v", err)
	}
	if calls["cert-a"] != 1 || calls["cert-b"] != 1 {
		t.Fatalf("expected both certificates to fetch once, got %+v", calls)
	}
	if len(mirrored) != 2 {
		t.Fatalf("expected 2 mirrored certificates, got %d", len(mirrored))
	}
	if got := string(mirrored[0].BundleZIP); got != "new-zip" {
		t.Fatalf("expected updated bundle for changed certificate, got %q", got)
	}
	if len(mirrored[1].BundleZIP) != 0 {
		t.Fatalf("expected unavailable certificate to have empty bundle")
	}
	if !next["cert-b"].materialUnavailable {
		t.Fatalf("expected unavailable certificate marker in cache")
	}
}

func TestClusterSyncCertificateSetDigestIgnoresOrder(t *testing.T) {
	a := certmgr.Certificate{ID: "a", Type: certmgr.TypeSelfSigned, Status: certmgr.StatusActive, UpdatedAt: time.Unix(1, 0).UTC()}
	b := certmgr.Certificate{ID: "b", Type: certmgr.TypeSelfSigned, Status: certmgr.StatusActive, UpdatedAt: time.Unix(2, 0).UTC()}
	first := clusterSyncCertificateSetDigest([]certmgr.Certificate{a, b})
	second := clusterSyncCertificateSetDigest([]certmgr.Certificate{b, a})
	if first != second {
		t.Fatalf("expected digest to be order-independent")
	}
}

func remoteSlice(items ...certmgr.Certificate) []certmgr.Certificate {
	return append([]certmgr.Certificate{}, items...)
}

type testErr string

func (e testErr) Error() string { return string(e) }
