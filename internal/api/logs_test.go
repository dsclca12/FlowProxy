package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"flowproxy/internal/proxy"
)

func TestHandleLogsSupportsRangeAndFilters(t *testing.T) {
	store, err := proxy.NewAccessLogStore(filepath.Join(t.TempDir(), "logs.json"), proxy.AccessLogStoreOptions{
		MaxRows:      100,
		RetentionTTL: 0,
		FlushEvery:   10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new access log store: %v", err)
	}
	defer func() { _ = store.Close() }()

	base := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	store.Append(proxy.AccessLogEntry{Timestamp: base.Add(-2 * time.Hour), SiteID: "site-a", Domain: "a.example.com", StatusCode: 200, Path: "/ok"})
	store.Append(proxy.AccessLogEntry{Timestamp: base.Add(-30 * time.Minute), SiteID: "site-b", Domain: "b.example.com", StatusCode: 404, Path: "/nf"})
	store.Append(proxy.AccessLogEntry{Timestamp: base, SiteID: "site-b", Domain: "b.example.com", StatusCode: 503, Path: "/err"})

	router := proxy.NewRouter()
	router.SetAccessLogStore(store)
	server := &Server{router: router}

	req := httptest.NewRequest(http.MethodGet, "/api/logs?limit=10&from=2026-04-16T11:00:00Z&to=2026-04-16T12:00:00Z&siteId=site-b&statusMin=400&statusMax=599", nil)
	rec := httptest.NewRecorder()
	server.handleLogs(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var got []proxy.AccessLogEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 logs, got %d", len(got))
	}
	if got[0].Path != "/err" || got[1].Path != "/nf" {
		t.Fatalf("unexpected logs: %+v", got)
	}
}

func TestHandleLogsRejectsInvalidFrom(t *testing.T) {
	router := proxy.NewRouter()
	server := &Server{router: router}

	req := httptest.NewRequest(http.MethodGet, "/api/logs?from=not-a-time", nil)
	rec := httptest.NewRecorder()
	server.handleLogs(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
