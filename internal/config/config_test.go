package config

import "testing"

func TestNormalizeListenAddr(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "already colon", in: ":8443", want: ":8443"},
		{name: "number only", in: "8443", want: ":8443"},
		{name: "host and port", in: "0.0.0.0:8443", want: "0.0.0.0:8443"},
		{name: "trim spaces", in: " 8443 ", want: ":8443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeListenAddr(tt.in); got != tt.want {
				t.Fatalf("normalizeListenAddr(%q)=%q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestLoadAdminDefaultsHardened(t *testing.T) {
	t.Setenv("ADMIN_ADDR", "")
	t.Setenv("ADMIN_USERNAME", "")
	t.Setenv("ADMIN_PASSWORD", "")

	cfg := Load()
	if cfg.AdminAddr != "0.0.0.0:9000" {
		t.Fatalf("unexpected default admin addr: %s", cfg.AdminAddr)
	}
	if cfg.AdminUsername != "" {
		t.Fatalf("unexpected default admin username: %q", cfg.AdminUsername)
	}
	if cfg.AdminPassword != "" {
		t.Fatalf("unexpected default admin password: %q", cfg.AdminPassword)
	}
	if cfg.StorageBackend != "file" {
		t.Fatalf("unexpected default storage backend: %q", cfg.StorageBackend)
	}
	if len(cfg.StorageEtcdEndpoints) != 0 {
		t.Fatalf("unexpected default etcd endpoints: %#v", cfg.StorageEtcdEndpoints)
	}
	if cfg.StorageEtcdPrefix != "/flowproxy" {
		t.Fatalf("unexpected default etcd prefix: %q", cfg.StorageEtcdPrefix)
	}
}

func TestNormalizeStorageBackend(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: "file"},
		{in: "file", want: "file"},
		{in: "FILE", want: "file"},
		{in: " etcd ", want: "etcd"},
		{in: "memory", want: "memory"},
	}
	for _, tt := range tests {
		if got := normalizeStorageBackend(tt.in); got != tt.want {
			t.Fatalf("normalizeStorageBackend(%q)=%q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLoadClusterSyncURLs(t *testing.T) {
	t.Setenv("CLUSTER_SYNC_URL", " https://a.example.com/ ")
	t.Setenv("CLUSTER_SYNC_URLS", "https://b.example.com/, https://a.example.com , ,https://c.example.com")
	cfg := Load()
	if cfg.ClusterSyncURL != "https://a.example.com" {
		t.Fatalf("unexpected cluster sync url: %q", cfg.ClusterSyncURL)
	}
	if len(cfg.ClusterSyncURLs) != 3 {
		t.Fatalf("unexpected cluster sync urls: %#v", cfg.ClusterSyncURLs)
	}
	if cfg.ClusterSyncURLs[0] != "https://b.example.com" || cfg.ClusterSyncURLs[1] != "https://a.example.com" || cfg.ClusterSyncURLs[2] != "https://c.example.com" {
		t.Fatalf("unexpected cluster sync urls order/content: %#v", cfg.ClusterSyncURLs)
	}
}
