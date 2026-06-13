package proxy

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAccessLogStorePersistAndQuery(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "access-logs.json")
	store, err := NewAccessLogStore(logPath, AccessLogStoreOptions{
		MaxRows:      100,
		RetentionTTL: 0,
		FlushEvery:   10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new access log store: %v", err)
	}

	base := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)
	store.Append(AccessLogEntry{Timestamp: base.Add(-2 * time.Hour), SiteID: "site-a", Domain: "a.example.com", StatusCode: 200, Path: "/ok"})
	store.Append(AccessLogEntry{Timestamp: base.Add(-1 * time.Hour), SiteID: "site-b", Domain: "b.example.com", StatusCode: 404, Path: "/missing"})
	store.Append(AccessLogEntry{Timestamp: base, SiteID: "site-b", Domain: "b.example.com", StatusCode: 503, Path: "/err"})

	got := store.Query(AccessLogQuery{Limit: 10})
	if len(got) != 3 {
		t.Fatalf("expected 3 logs, got %d", len(got))
	}
	if got[0].Path != "/err" || got[1].Path != "/missing" || got[2].Path != "/ok" {
		t.Fatalf("unexpected order: %+v", got)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	reopened, err := NewAccessLogStore(logPath, AccessLogStoreOptions{
		MaxRows:      100,
		RetentionTTL: 0,
		FlushEvery:   10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("reopen access log store: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	from := base.Add(-90 * time.Minute)
	to := base
	filtered := reopened.Query(AccessLogQuery{
		Limit:     10,
		From:      &from,
		To:        &to,
		SiteID:    "site-b",
		StatusMin: 400,
		StatusMax: 599,
	})
	if len(filtered) != 2 {
		t.Fatalf("expected 2 filtered logs, got %d", len(filtered))
	}
}

func TestAccessLogStorePruneByMaxRowsAndTTL(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "access-logs.json")
	store, err := NewAccessLogStore(logPath, AccessLogStoreOptions{
		MaxRows:      2,
		RetentionTTL: time.Hour,
		FlushEvery:   10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new access log store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()
	store.Append(AccessLogEntry{Timestamp: now.Add(-3 * time.Hour), Path: "/old", StatusCode: 200})
	store.Append(AccessLogEntry{Timestamp: now.Add(-30 * time.Minute), Path: "/mid", StatusCode: 200})
	store.Append(AccessLogEntry{Timestamp: now.Add(-10 * time.Minute), Path: "/newer", StatusCode: 200})
	store.Append(AccessLogEntry{Timestamp: now, Path: "/latest", StatusCode: 200})

	got := store.Query(AccessLogQuery{Limit: 10})
	if len(got) != 2 {
		t.Fatalf("expected 2 logs after prune, got %d", len(got))
	}
	if got[0].Path != "/latest" || got[1].Path != "/newer" {
		t.Fatalf("unexpected remaining logs: %+v", got)
	}
}
