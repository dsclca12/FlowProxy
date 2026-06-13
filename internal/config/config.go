package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AdminAddr              string
	AdminHTTPSAddr         string
	AdminTLSCertFile       string
	AdminTLSKeyFile        string
	AdminTLSCertificateID  string
	AdminTLSAutoSelfSigned bool
	AdminTLSRedirectHTTP   bool
	HTTPAddr               string
	HTTPSAddr              string
	AdminUsername          string
	AdminPassword          string
	AdminAuthFile          string
	TrustedProxyCIDRs      []string
	DataFile               string
	SettingsFile           string
	CertDataFile           string
	CertDir                string
	BackupDir              string
	AccessLogFile          string
	AccessLogMaxRows       int
	AccessLogTTL           time.Duration
	AccessLogFlush         time.Duration
	AlertWebhookURL        string
	AlertConsecutive5xx    int
	AlertLatencyMs         int
	AlertCooldown          time.Duration
	LetsEncryptEmail       string
	EnableAutoTLS          bool
	EnableUI               bool
	NodeID                 string
	NodeName               string
	NodeDataFile           string
	ClusterSyncURL         string
	ClusterSyncURLs        []string
	ClusterSyncUsername    string
	ClusterSyncPassword    string
	ClusterSyncInterval    time.Duration
	StorageBackend         string
	StorageEtcdEndpoints   []string
	StorageEtcdPrefix      string
	StorageEtcdDialTimeout time.Duration
	ConfigFile             string
}

func Load() Config {
	return Config{
		AdminAddr:              normalizeListenAddr(env("ADMIN_ADDR", "0.0.0.0:9000")),
		AdminHTTPSAddr:         normalizeListenAddr(strings.TrimSpace(os.Getenv("ADMIN_HTTPS_ADDR"))),
		AdminTLSCertFile:       strings.TrimSpace(os.Getenv("ADMIN_TLS_CERT_FILE")),
		AdminTLSKeyFile:        strings.TrimSpace(os.Getenv("ADMIN_TLS_KEY_FILE")),
		AdminTLSCertificateID:  strings.TrimSpace(os.Getenv("ADMIN_TLS_CERTIFICATE_ID")),
		AdminTLSAutoSelfSigned: envBool("ADMIN_TLS_AUTO_SELF_SIGNED", true),
		AdminTLSRedirectHTTP:   envBool("ADMIN_TLS_REDIRECT_HTTP", false),
		HTTPAddr:               normalizeListenAddr(env("HTTP_ADDR", ":80")),
		HTTPSAddr:              normalizeListenAddr(env("HTTPS_ADDR", ":443")),
		AdminUsername:          strings.TrimSpace(env("ADMIN_USERNAME", "")),
		AdminPassword:          env("ADMIN_PASSWORD", ""),
		AdminAuthFile:          env("ADMIN_AUTH_FILE", "./data/admin-auth.json"),
		TrustedProxyCIDRs:      envCSV("TRUSTED_PROXY_CIDRS", []string{"127.0.0.1/32", "::1/128"}),
		DataFile:               env("DATA_FILE", "./data/sites.json"),
		SettingsFile:           env("SETTINGS_FILE", "./data/settings.json"),
		CertDataFile:           env("CERT_DATA_FILE", "./data/certificates.json"),
		CertDir:                env("CERT_DIR", "./data/certs"),
		BackupDir:              env("BACKUP_DIR", "./data/backups"),
		AccessLogFile:          env("ACCESS_LOG_FILE", "./data/access-logs.json"),
		AccessLogMaxRows:       envInt("ACCESS_LOG_MAX_ROWS", 10000),
		AccessLogTTL:           envDuration("ACCESS_LOG_TTL", 7*24*time.Hour),
		AccessLogFlush:         envDuration("ACCESS_LOG_FLUSH_INTERVAL", 2*time.Second),
		AlertWebhookURL:        strings.TrimSpace(os.Getenv("ALERT_WEBHOOK_URL")),
		AlertConsecutive5xx:    envInt("ALERT_CONSECUTIVE_5XX", 10),
		AlertLatencyMs:         envInt("ALERT_LATENCY_MS", 0),
		AlertCooldown:          envDuration("ALERT_COOLDOWN", 5*time.Minute),
		LetsEncryptEmail:       os.Getenv("LETSENCRYPT_EMAIL"),
		EnableAutoTLS:          envBool("ENABLE_AUTO_TLS", false),
		EnableUI:               envBool("ENABLE_UI", true),
		NodeID:                 strings.TrimSpace(env("NODE_ID", "default")),
		NodeName:               strings.TrimSpace(env("NODE_NAME", "Default Node")),
		NodeDataFile:           env("NODE_DATA_FILE", "./data/nodes.json"),
		ClusterSyncURL:         strings.TrimRight(strings.TrimSpace(env("CLUSTER_SYNC_URL", "")), "/"),
		ClusterSyncURLs:        normalizeURLs(envCSV("CLUSTER_SYNC_URLS", []string{})),
		ClusterSyncUsername:    strings.TrimSpace(env("CLUSTER_SYNC_USERNAME", "")),
		ClusterSyncPassword:    env("CLUSTER_SYNC_PASSWORD", ""),
		ClusterSyncInterval:    envDuration("CLUSTER_SYNC_INTERVAL", 3*time.Second),
		StorageBackend:         normalizeStorageBackend(env("STORAGE_BACKEND", "file")),
		StorageEtcdEndpoints:   envCSV("STORAGE_ETCD_ENDPOINTS", []string{}),
		StorageEtcdPrefix:      strings.TrimSpace(env("STORAGE_ETCD_PREFIX", "/flowproxy")),
		StorageEtcdDialTimeout: envDuration("STORAGE_ETCD_DIAL_TIMEOUT", 3*time.Second),
		ConfigFile:             detectConfigFile(),
	}
}

func env(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func envInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func envCSV(key string, fallback []string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return append([]string{}, fallback...)
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return append([]string{}, fallback...)
	}
	return out
}

func normalizeListenAddr(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return v
	}
	if strings.HasPrefix(v, ":") {
		return v
	}
	if _, err := strconv.Atoi(v); err == nil {
		return ":" + v
	}
	return v
}

func parseDurationField(raw string, field string, allowZero bool) (time.Duration, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, fmt.Errorf("%s cannot be empty", field)
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s is invalid duration: %w", field, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("%s must be >= 0", field)
	}
	if !allowZero && d == 0 {
		return 0, fmt.Errorf("%s must be > 0", field)
	}
	return d, nil
}

func normalizeStorageBackend(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "", "file":
		return "file"
	case "etcd":
		return "etcd"
	default:
		return value
	}
}

func normalizeURLs(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		value := strings.TrimRight(strings.TrimSpace(item), "/")
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func detectConfigFile() string {
	raw := strings.TrimSpace(os.Getenv("CONFIG_FILE"))
	if raw != "" {
		return raw
	}
	defaultPath := "./flowproxy.yaml"
	if _, err := os.Stat(defaultPath); err == nil {
		return filepath.Clean(defaultPath)
	}
	return ""
}
