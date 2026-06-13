package ipcountry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flowproxy/internal/settings"
)

func TestFetchCIDRsForTaskFromIPDeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ipblocks/data/countries/cn.zone":
			_, _ = w.Write([]byte("1.0.1.0/24\n1.0.2.0/23\n# comment\ninvalid\n"))
		case "/ipv6/ipaddresses/aggregated/cn-aggregated.zone":
			_, _ = w.Write([]byte("2400:3200::/32\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	prevBase := ipDenyBaseURL
	ipDenyBaseURL = srv.URL
	defer func() { ipDenyBaseURL = prevBase }()

	task := settings.IPCountryAutoUpdate{
		Source:      "ipdeny",
		Countries:   []string{"CN"},
		IncludeIPv6: true,
	}
	cidrs, err := fetchCIDRsForTask(context.Background(), srv.Client(), task)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}
	got := strings.Join(cidrs, ",")
	if got != "1.0.1.0/24,1.0.2.0/23,2400:3200::/32" {
		t.Fatalf("unexpected cidrs: %v", cidrs)
	}
}

func TestUpdaterSyncNowPersistsResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ipblocks/data/countries/cn.zone" {
			_, _ = w.Write([]byte("1.0.1.0/24\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	prevBase := ipDenyBaseURL
	ipDenyBaseURL = srv.URL
	defer func() { ipDenyBaseURL = prevBase }()

	settingsFile := filepath.Join(t.TempDir(), "settings.json")
	st, err := settings.New(settingsFile, settings.Settings{
		Language: "en",
		WebPort:  9000,
		IPRuleSets: []settings.IPRuleSet{
			{ID: "office"},
		},
		IPCountryAutoUpdates: []settings.IPCountryAutoUpdate{
			{
				ID:        "cn-office-allow",
				Enabled:   true,
				RuleSetID: "office",
				List:      "allow",
				Countries: []string{"CN"},
				Interval:  "5m",
				Source:    "ipdeny",
			},
		},
	})
	if err != nil {
		t.Fatalf("new settings store failed: %v", err)
	}

	updateCount := 0
	updater := NewUpdater(st, func(_ settings.Settings) {
		updateCount++
	})
	now := time.Date(2026, 4, 18, 10, 0, 0, 0, time.UTC)
	updater.syncNow(now)

	got := st.Get()
	if updateCount != 1 {
		t.Fatalf("expected 1 callback, got %d", updateCount)
	}
	task := got.IPCountryAutoUpdates[0]
	if len(task.CIDRs) != 1 || task.CIDRs[0] != "1.0.1.0/24" {
		t.Fatalf("unexpected cidrs: %#v", task.CIDRs)
	}
	if task.LastAttemptAt.IsZero() || task.LastSyncAt.IsZero() {
		t.Fatalf("expected lastAttemptAt/lastSyncAt to be set")
	}
	if task.LastError != "" {
		t.Fatalf("expected empty lastError, got %s", task.LastError)
	}

	updater.syncNow(now.Add(1 * time.Minute))
	if updateCount != 1 {
		t.Fatalf("unexpected callback count for non-due run: %d", updateCount)
	}

	updater.syncNow(now.Add(6 * time.Minute))
	if updateCount != 2 {
		t.Fatalf("expected callback for due run, got %d", updateCount)
	}
}
