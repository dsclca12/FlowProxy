package store

import (
	"path/filepath"
	"testing"

	"flowproxy/internal/site"
)

func TestStoreCRUD(t *testing.T) {
	tmp := t.TempDir()
	st, err := New(filepath.Join(tmp, "sites.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	in := site.Site{
		ID:         "a1",
		Domain:     "Example.com",
		Upstream:   "http://127.0.0.1:8080",
		Enabled:    true,
		ForceHTTPS: true,
	}
	got, err := st.Create(in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.Domain != "example.com" {
		t.Fatalf("normalized domain mismatch: %s", got.Domain)
	}

	updated, err := st.Update("a1", site.Site{
		Domain:     "api.example.com",
		Upstream:   "http://127.0.0.1:9090",
		Enabled:    false,
		ForceHTTPS: false,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Upstream != "http://127.0.0.1:9090" || updated.Enabled {
		t.Fatalf("update did not apply")
	}

	if _, err := st.SetEnabled("a1", true); err != nil {
		t.Fatalf("set enabled: %v", err)
	}

	if err := st.Delete("a1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.Get("a1"); err == nil {
		t.Fatalf("expected not found after delete")
	}
}

func TestStoreRejectsDuplicateEnabledListenPort(t *testing.T) {
	tmp := t.TempDir()
	st, err := New(filepath.Join(tmp, "sites.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	_, err = st.Create(site.Site{
		ID:         "a1",
		ListenPort: 2001,
		Upstream:   "http://127.0.0.1:8080",
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("create first site: %v", err)
	}

	if _, err := st.Create(site.Site{
		ID:         "a2",
		ListenPort: 2001,
		Upstream:   "http://127.0.0.1:8081",
		Enabled:    true,
	}); err == nil {
		t.Fatalf("expected duplicate listen port error")
	}
}

func TestStoreAllowsSameDomainOnDifferentNodes(t *testing.T) {
	tmp := t.TempDir()
	st, err := New(filepath.Join(tmp, "sites.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	if _, err := st.Create(site.Site{
		ID:       "a1",
		NodeID:   "node-a",
		Domain:   "example.com",
		Upstream: "http://127.0.0.1:8080",
		Enabled:  true,
	}); err != nil {
		t.Fatalf("create first site: %v", err)
	}

	if _, err := st.Create(site.Site{
		ID:       "a2",
		NodeID:   "node-b",
		Domain:   "example.com",
		Upstream: "http://127.0.0.1:8081",
		Enabled:  true,
	}); err != nil {
		t.Fatalf("expected same domain on different nodes to be allowed, got %v", err)
	}
}

func TestStoreAllowsSameListenPortOnDifferentNodes(t *testing.T) {
	tmp := t.TempDir()
	st, err := New(filepath.Join(tmp, "sites.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	if _, err := st.Create(site.Site{
		ID:         "a1",
		NodeID:     "node-a",
		ListenPort: 2001,
		Domain:     "a.example.com",
		Upstream:   "http://127.0.0.1:8080",
		Enabled:    true,
	}); err != nil {
		t.Fatalf("create first site: %v", err)
	}

	if _, err := st.Create(site.Site{
		ID:         "a2",
		NodeID:     "node-b",
		ListenPort: 2001,
		Domain:     "b.example.com",
		Upstream:   "http://127.0.0.1:8081",
		Enabled:    true,
	}); err != nil {
		t.Fatalf("expected same listen port on different nodes to be allowed, got %v", err)
	}
}

func TestStoreUpdatePreservesExtendedFields(t *testing.T) {
	tmp := t.TempDir()
	st, err := New(filepath.Join(tmp, "sites.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	created, err := st.Create(site.Site{
		ID:                  "a1",
		Domain:              "example.com",
		Upstream:            "http://127.0.0.1:8080",
		Enabled:             true,
		AutoRequestHeaders:  true,
		AutoResponseHeaders: true,
		IPRuleSetIDs:        []string{"office", "cdn"},
		Cache: site.CacheConfig{
			Enabled:    true,
			TTLSeconds: 60,
		},
		Gzip:   site.GzipConfig{Enabled: true},
		Brotli: site.BrotliConfig{Enabled: true},
		Timeouts: site.TimeoutConfig{
			RequestMillis: 1500,
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	created.Upstream = "http://127.0.0.1:9090"
	updated, err := st.Update("a1", created)
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	if !updated.Cache.Enabled || updated.Cache.TTLSeconds != 60 {
		t.Fatalf("cache lost after update: %+v", updated.Cache)
	}
	if !updated.Gzip.Enabled || !updated.Brotli.Enabled {
		t.Fatalf("compression fields lost after update: gzip=%+v brotli=%+v", updated.Gzip, updated.Brotli)
	}
	if updated.Timeouts.RequestMillis != 1500 {
		t.Fatalf("timeouts lost after update: %+v", updated.Timeouts)
	}
	if !updated.AutoRequestHeaders || !updated.AutoResponseHeaders {
		t.Fatalf("auto header flags lost after update")
	}
	if len(updated.IPRuleSetIDs) != 2 || updated.IPRuleSetIDs[0] != "office" || updated.IPRuleSetIDs[1] != "cdn" {
		t.Fatalf("ipRuleSetIds lost after update: %#v", updated.IPRuleSetIDs)
	}
}

func TestStoreListReturnsDeepCopy(t *testing.T) {
	tmp := t.TempDir()
	st, err := New(filepath.Join(tmp, "sites.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	_, err = st.Create(site.Site{
		ID:                "a1",
		Domain:            "example.com",
		Upstream:          "http://127.0.0.1:8080",
		Enabled:           true,
		AdditionalDomains: []string{"api.example.com"},
		Routes: []site.RouteRule{{
			Path:     "/api",
			Methods:  []string{"GET"},
			Upstream: "http://127.0.0.1:8081",
		}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	items := st.List()
	items[0].AdditionalDomains[0] = "mutated.example.com"
	items[0].Routes[0].Methods[0] = "POST"

	reloaded := st.List()
	if reloaded[0].AdditionalDomains[0] != "api.example.com" {
		t.Fatalf("additional domains leaked through shallow copy: %#v", reloaded[0].AdditionalDomains)
	}
	if reloaded[0].Routes[0].Methods[0] != "GET" {
		t.Fatalf("route methods leaked through shallow copy: %#v", reloaded[0].Routes[0].Methods)
	}
}
