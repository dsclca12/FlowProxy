package clustersync

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewSupportsBaseURLsOnly(t *testing.T) {
	client, err := New(Config{
		BaseURLs: []string{"https://controller-a.example.com", "https://controller-b.example.com"},
		Username: "u",
		Password: "p",
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if len(client.baseURLs) != 2 {
		t.Fatalf("unexpected base url count: %d", len(client.baseURLs))
	}
}

func TestFetchSettingsFailoverToNextEndpoint(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "primary down", http.StatusServiceUnavailable)
	}))
	defer primary.Close()

	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/login":
			w.WriteHeader(http.StatusNoContent)
		case "/api/settings":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"language": "en",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer secondary.Close()

	client, err := New(Config{
		BaseURL:  primary.URL,
		BaseURLs: []string{secondary.URL},
		Username: "admin",
		Password: "secret",
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, err := client.FetchSettings()
	if err != nil {
		t.Fatalf("FetchSettings() error = %v", err)
	}
	if got.Language != "en" {
		t.Fatalf("unexpected settings after failover: %+v", got)
	}
	if client.ActiveEndpoint() != secondary.URL {
		t.Fatalf("unexpected active endpoint after failover: %s", client.ActiveEndpoint())
	}
}

func TestPrioritizeEligibleEndpointsSkipsCoolingEndpoint(t *testing.T) {
	client, err := New(Config{
		BaseURLs: []string{"https://a.example.com", "https://b.example.com"},
		Username: "u",
		Password: "p",
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	now := time.Now().UTC()
	client.cooldownUntil["https://a.example.com"] = now.Add(30 * time.Second)
	client.activeIndex = 0
	ordered := client.prioritizeEligibleEndpoints(client.baseURLs, 0, now)
	if len(ordered) != 2 || ordered[0] != "https://b.example.com" {
		t.Fatalf("unexpected endpoint order with cooldown: %#v", ordered)
	}
}

func TestFailoverCooldownCapped(t *testing.T) {
	if d := failoverCooldown(1); d != 2*time.Second {
		t.Fatalf("unexpected cooldown for first failure: %v", d)
	}
	if d := failoverCooldown(10); d != 60*time.Second {
		t.Fatalf("unexpected cooldown cap: %v", d)
	}
}
