package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
	syaml "sigs.k8s.io/yaml"

	"flowproxy/internal/certmgr"
	"flowproxy/internal/settings"
	"flowproxy/internal/site"
)

const configFileVersion = 1

type FileConfig struct {
	Version      int                    `json:"version"`
	Runtime      *RuntimeFileConfig     `json:"runtime"`
	Settings     *settings.Settings     `json:"settings"`
	Sites        *[]site.Site           `json:"sites"`
	Certificates *[]certmgr.Certificate `json:"certificates"`
}

type RuntimeFileConfig struct {
	AdminAddr              *string   `json:"adminAddr"`
	AdminHTTPSAddr         *string   `json:"adminHttpsAddr"`
	AdminTLSCertFile       *string   `json:"adminTlsCertFile"`
	AdminTLSKeyFile        *string   `json:"adminTlsKeyFile"`
	AdminTLSCertificateID  *string   `json:"adminTlsCertificateId"`
	AdminTLSAutoSelfSigned *bool     `json:"adminTlsAutoSelfSigned"`
	AdminTLSRedirectHTTP   *bool     `json:"adminTlsRedirectHttp"`
	HTTPAddr               *string   `json:"httpAddr"`
	HTTPSAddr              *string   `json:"httpsAddr"`
	AdminUsername          *string   `json:"adminUsername"`
	AdminPassword          *string   `json:"adminPassword"`
	AdminAuthFile          *string   `json:"adminAuthFile"`
	TrustedProxyCIDRs      *[]string `json:"trustedProxyCidrs"`
	DataFile               *string   `json:"dataFile"`
	SettingsFile           *string   `json:"settingsFile"`
	CertDataFile           *string   `json:"certDataFile"`
	CertDir                *string   `json:"certDir"`
	BackupDir              *string   `json:"backupDir"`
	AccessLogFile          *string   `json:"accessLogFile"`
	AccessLogMaxRows       *int      `json:"accessLogMaxRows"`
	AccessLogTTL           *string   `json:"accessLogTTL"`
	AccessLogFlush         *string   `json:"accessLogFlushInterval"`
	AlertWebhookURL        *string   `json:"alertWebhookUrl"`
	AlertConsecutive5xx    *int      `json:"alertConsecutive5xx"`
	AlertLatencyMs         *int      `json:"alertLatencyMs"`
	AlertCooldown          *string   `json:"alertCooldown"`
	LetsEncryptEmail       *string   `json:"letsEncryptEmail"`
	EnableAutoTLS          *bool     `json:"enableAutoTLS"`
	EnableUI               *bool     `json:"enableUI"`
	NodeID                 *string   `json:"nodeId"`
	NodeName               *string   `json:"nodeName"`
	NodeDataFile           *string   `json:"nodeDataFile"`
	ClusterSyncURL         *string   `json:"clusterSyncUrl"`
	ClusterSyncURLs        *[]string `json:"clusterSyncUrls"`
	ClusterSyncUsername    *string   `json:"clusterSyncUsername"`
	ClusterSyncPassword    *string   `json:"clusterSyncPassword"`
	ClusterSyncInterval    *string   `json:"clusterSyncInterval"`
	StorageBackend         *string   `json:"storageBackend"`
	StorageEtcdEndpoints   *[]string `json:"storageEtcdEndpoints"`
	StorageEtcdPrefix      *string   `json:"storageEtcdPrefix"`
	StorageEtcdDialTimeout *string   `json:"storageEtcdDialTimeout"`
}

type certPersistModel struct {
	Certificates []certmgr.Certificate `json:"certificates"`
}

func LoadFromFile(path string) (*FileConfig, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("config file %s is empty", path)
	}

	var fileCfg FileConfig
	if err := syaml.UnmarshalStrict(data, &fileCfg, syaml.DisallowUnknownFields); err != nil {
		return nil, fmt.Errorf("decode config file %s: %w", path, err)
	}

	if fileCfg.Version == 0 {
		fileCfg.Version = configFileVersion
	}
	if fileCfg.Version != configFileVersion {
		return nil, fmt.Errorf("unsupported config version: %d", fileCfg.Version)
	}

	if err := normalizeFileConfig(&fileCfg); err != nil {
		return nil, err
	}
	return &fileCfg, nil
}

func (c *Config) ApplyRuntimeFile(runtime *RuntimeFileConfig) error {
	if runtime == nil {
		return nil
	}

	if runtime.AdminAddr != nil {
		addr := normalizeListenAddr(*runtime.AdminAddr)
		if addr == "" {
			return fmt.Errorf("runtime.adminAddr cannot be empty")
		}
		c.AdminAddr = addr
	}
	if runtime.AdminHTTPSAddr != nil {
		addr := normalizeListenAddr(*runtime.AdminHTTPSAddr)
		c.AdminHTTPSAddr = addr
	}
	if runtime.AdminTLSCertFile != nil {
		c.AdminTLSCertFile = strings.TrimSpace(*runtime.AdminTLSCertFile)
	}
	if runtime.AdminTLSKeyFile != nil {
		c.AdminTLSKeyFile = strings.TrimSpace(*runtime.AdminTLSKeyFile)
	}
	if runtime.AdminTLSCertificateID != nil {
		c.AdminTLSCertificateID = strings.TrimSpace(*runtime.AdminTLSCertificateID)
	}
	if runtime.AdminTLSAutoSelfSigned != nil {
		c.AdminTLSAutoSelfSigned = *runtime.AdminTLSAutoSelfSigned
	}
	if runtime.AdminTLSRedirectHTTP != nil {
		c.AdminTLSRedirectHTTP = *runtime.AdminTLSRedirectHTTP
	}
	if runtime.HTTPAddr != nil {
		addr := normalizeListenAddr(*runtime.HTTPAddr)
		if addr == "" {
			return fmt.Errorf("runtime.httpAddr cannot be empty")
		}
		c.HTTPAddr = addr
	}
	if runtime.HTTPSAddr != nil {
		addr := normalizeListenAddr(*runtime.HTTPSAddr)
		if addr == "" {
			return fmt.Errorf("runtime.httpsAddr cannot be empty")
		}
		c.HTTPSAddr = addr
	}
	if runtime.AdminUsername != nil {
		c.AdminUsername = strings.TrimSpace(*runtime.AdminUsername)
	}
	if runtime.AdminPassword != nil {
		c.AdminPassword = strings.TrimSpace(*runtime.AdminPassword)
	}
	if runtime.AdminAuthFile != nil {
		p := strings.TrimSpace(*runtime.AdminAuthFile)
		if p == "" {
			return fmt.Errorf("runtime.adminAuthFile cannot be empty")
		}
		c.AdminAuthFile = filepath.Clean(p)
	}
	if runtime.TrustedProxyCIDRs != nil {
		items := make([]string, 0, len(*runtime.TrustedProxyCIDRs))
		seen := map[string]struct{}{}
		for _, item := range *runtime.TrustedProxyCIDRs {
			value := strings.TrimSpace(item)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			items = append(items, value)
		}
		c.TrustedProxyCIDRs = items
	}

	if runtime.DataFile != nil {
		p := strings.TrimSpace(*runtime.DataFile)
		if p == "" {
			return fmt.Errorf("runtime.dataFile cannot be empty")
		}
		c.DataFile = filepath.Clean(p)
	}
	if runtime.SettingsFile != nil {
		p := strings.TrimSpace(*runtime.SettingsFile)
		if p == "" {
			return fmt.Errorf("runtime.settingsFile cannot be empty")
		}
		c.SettingsFile = filepath.Clean(p)
	}
	if runtime.CertDataFile != nil {
		p := strings.TrimSpace(*runtime.CertDataFile)
		if p == "" {
			return fmt.Errorf("runtime.certDataFile cannot be empty")
		}
		c.CertDataFile = filepath.Clean(p)
	}
	if runtime.CertDir != nil {
		p := strings.TrimSpace(*runtime.CertDir)
		if p == "" {
			return fmt.Errorf("runtime.certDir cannot be empty")
		}
		c.CertDir = filepath.Clean(p)
	}
	if runtime.BackupDir != nil {
		p := strings.TrimSpace(*runtime.BackupDir)
		if p == "" {
			return fmt.Errorf("runtime.backupDir cannot be empty")
		}
		c.BackupDir = filepath.Clean(p)
	}
	if runtime.AccessLogFile != nil {
		p := strings.TrimSpace(*runtime.AccessLogFile)
		if p == "" {
			return fmt.Errorf("runtime.accessLogFile cannot be empty")
		}
		c.AccessLogFile = filepath.Clean(p)
	}
	if runtime.AccessLogMaxRows != nil {
		if *runtime.AccessLogMaxRows <= 0 {
			return fmt.Errorf("runtime.accessLogMaxRows must be > 0")
		}
		c.AccessLogMaxRows = *runtime.AccessLogMaxRows
	}
	if runtime.AccessLogTTL != nil {
		ttl, err := parseDurationField(*runtime.AccessLogTTL, "runtime.accessLogTTL", true)
		if err != nil {
			return err
		}
		c.AccessLogTTL = ttl
	}
	if runtime.AccessLogFlush != nil {
		flush, err := parseDurationField(*runtime.AccessLogFlush, "runtime.accessLogFlushInterval", false)
		if err != nil {
			return err
		}
		c.AccessLogFlush = flush
	}
	if runtime.AlertWebhookURL != nil {
		c.AlertWebhookURL = strings.TrimSpace(*runtime.AlertWebhookURL)
	}
	if runtime.AlertConsecutive5xx != nil {
		if *runtime.AlertConsecutive5xx < 0 {
			return fmt.Errorf("runtime.alertConsecutive5xx must be >= 0")
		}
		c.AlertConsecutive5xx = *runtime.AlertConsecutive5xx
	}
	if runtime.AlertLatencyMs != nil {
		if *runtime.AlertLatencyMs < 0 {
			return fmt.Errorf("runtime.alertLatencyMs must be >= 0")
		}
		c.AlertLatencyMs = *runtime.AlertLatencyMs
	}
	if runtime.AlertCooldown != nil {
		cooldown, err := parseDurationField(*runtime.AlertCooldown, "runtime.alertCooldown", false)
		if err != nil {
			return err
		}
		c.AlertCooldown = cooldown
	}
	if runtime.LetsEncryptEmail != nil {
		c.LetsEncryptEmail = strings.TrimSpace(*runtime.LetsEncryptEmail)
	}
	if runtime.EnableAutoTLS != nil {
		c.EnableAutoTLS = *runtime.EnableAutoTLS
	}
	if runtime.EnableUI != nil {
		c.EnableUI = *runtime.EnableUI
	}
	if runtime.NodeID != nil {
		c.NodeID = strings.TrimSpace(*runtime.NodeID)
	}
	if runtime.NodeName != nil {
		c.NodeName = strings.TrimSpace(*runtime.NodeName)
	}
	if runtime.NodeDataFile != nil {
		p := strings.TrimSpace(*runtime.NodeDataFile)
		if p == "" {
			return fmt.Errorf("runtime.nodeDataFile cannot be empty")
		}
		c.NodeDataFile = filepath.Clean(p)
	}
	if runtime.ClusterSyncURL != nil {
		c.ClusterSyncURL = strings.TrimRight(strings.TrimSpace(*runtime.ClusterSyncURL), "/")
	}
	if runtime.ClusterSyncURLs != nil {
		c.ClusterSyncURLs = normalizeURLs(*runtime.ClusterSyncURLs)
	}
	if runtime.ClusterSyncUsername != nil {
		c.ClusterSyncUsername = strings.TrimSpace(*runtime.ClusterSyncUsername)
	}
	if runtime.ClusterSyncPassword != nil {
		c.ClusterSyncPassword = strings.TrimSpace(*runtime.ClusterSyncPassword)
	}
	if runtime.ClusterSyncInterval != nil {
		interval, err := parseDurationField(*runtime.ClusterSyncInterval, "runtime.clusterSyncInterval", false)
		if err != nil {
			return err
		}
		c.ClusterSyncInterval = interval
	}
	if runtime.StorageBackend != nil {
		backend := normalizeStorageBackend(*runtime.StorageBackend)
		if backend != "file" && backend != "etcd" {
			return fmt.Errorf("runtime.storageBackend must be file or etcd")
		}
		c.StorageBackend = backend
	}
	if runtime.StorageEtcdEndpoints != nil {
		items := make([]string, 0, len(*runtime.StorageEtcdEndpoints))
		seen := map[string]struct{}{}
		for _, item := range *runtime.StorageEtcdEndpoints {
			value := strings.TrimSpace(item)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			items = append(items, value)
		}
		c.StorageEtcdEndpoints = items
	}
	if runtime.StorageEtcdPrefix != nil {
		prefix := strings.TrimSpace(*runtime.StorageEtcdPrefix)
		if prefix == "" {
			return fmt.Errorf("runtime.storageEtcdPrefix cannot be empty")
		}
		c.StorageEtcdPrefix = prefix
	}
	if runtime.StorageEtcdDialTimeout != nil {
		timeout, err := parseDurationField(*runtime.StorageEtcdDialTimeout, "runtime.storageEtcdDialTimeout", false)
		if err != nil {
			return err
		}
		c.StorageEtcdDialTimeout = timeout
	}

	return nil
}

func ApplyDataFileConfig(cfg Config, fileCfg *FileConfig) error {
	if fileCfg == nil {
		return nil
	}

	if fileCfg.Settings != nil {
		if err := writeJSONFile(cfg.SettingsFile, fileCfg.Settings); err != nil {
			return fmt.Errorf("write settings config: %w", err)
		}
	}
	if fileCfg.Sites != nil {
		if err := writeJSONFile(cfg.DataFile, fileCfg.Sites); err != nil {
			return fmt.Errorf("write sites config: %w", err)
		}
	}
	if fileCfg.Certificates != nil {
		model := certPersistModel{Certificates: *fileCfg.Certificates}
		if err := writeJSONFile(cfg.CertDataFile, model); err != nil {
			return fmt.Errorf("write certificates config: %w", err)
		}
	}
	return nil
}

func writeJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func normalizeFileConfig(cfg *FileConfig) error {
	if cfg.Settings != nil {
		normalizedSettings, err := settings.Normalize(*cfg.Settings)
		if err != nil {
			return fmt.Errorf("settings: %w", err)
		}
		cfg.Settings = &normalizedSettings
	}

	if cfg.Sites != nil {
		normalizedSites := make([]site.Site, 0, len(*cfg.Sites))
		ids := map[string]struct{}{}
		for i, item := range *cfg.Sites {
			var err error
			item, err = normalizeSiteFromFile(item)
			if err != nil {
				return fmt.Errorf("sites[%d]: %w", i, err)
			}
			if item.ID == "" {
				item.ID = newID()
			}
			if _, exists := ids[item.ID]; exists {
				return fmt.Errorf("sites[%d]: duplicate id %s", i, item.ID)
			}
			ids[item.ID] = struct{}{}
			normalizedSites = append(normalizedSites, item)
		}
		if err := ensureSiteUniqueness(normalizedSites); err != nil {
			return err
		}
		cfg.Sites = &normalizedSites
	}

	if cfg.Certificates != nil {
		normalizedCerts := make([]certmgr.Certificate, 0, len(*cfg.Certificates))
		ids := map[string]struct{}{}
		for i, item := range *cfg.Certificates {
			item.ID = strings.TrimSpace(item.ID)
			item.Name = strings.TrimSpace(item.Name)
			if item.ID == "" {
				item.ID = newID()
			}
			if _, exists := ids[item.ID]; exists {
				return fmt.Errorf("certificates[%d]: duplicate id %s", i, item.ID)
			}
			ids[item.ID] = struct{}{}
			normalizedCerts = append(normalizedCerts, item)
		}
		cfg.Certificates = &normalizedCerts
	}

	if cfg.Sites != nil && cfg.Certificates != nil {
		certIDs := map[string]struct{}{}
		for _, item := range *cfg.Certificates {
			certIDs[item.ID] = struct{}{}
		}
		for i, item := range *cfg.Sites {
			certID := strings.TrimSpace(item.CertificateID)
			if certID == "" {
				continue
			}
			if _, ok := certIDs[certID]; !ok {
				return fmt.Errorf("sites[%d]: certificateId %s not found in certificates", i, certID)
			}
		}
	}

	return nil
}

func normalizeSiteFromFile(item site.Site) (site.Site, error) {
	item.ID = strings.TrimSpace(item.ID)
	item.Name = strings.TrimSpace(item.Name)
	item.BasicAuth.Username = strings.TrimSpace(item.BasicAuth.Username)
	item.BasicAuth.Password = strings.TrimSpace(item.BasicAuth.Password)
	item.BasicAuth.PasswordHash = strings.TrimSpace(item.BasicAuth.PasswordHash)
	item.TrafficControl.AllowedMethods = site.NormalizeHTTPMethods(item.TrafficControl.AllowedMethods)
	item.Security.BlockUserAgentPatterns = normalizeStringList(item.Security.BlockUserAgentPatterns)
	item.UpstreamTLS.ServerName = strings.TrimSpace(item.UpstreamTLS.ServerName)
	item.UpstreamTLS.RootCAFile = strings.TrimSpace(item.UpstreamTLS.RootCAFile)
	item.UpstreamTLS.RootCAPEM = strings.TrimSpace(item.UpstreamTLS.RootCAPEM)
	item.Resilience.ActiveHealthCheck.Path = strings.TrimSpace(item.Resilience.ActiveHealthCheck.Path)
	item.Resilience.Retry.RetryOnStatuses = site.NormalizeStatusCodes(item.Resilience.Retry.RetryOnStatuses)
	item.Resilience.Retry.BackoffStrategy = strings.ToLower(strings.TrimSpace(item.Resilience.Retry.BackoffStrategy))
	item.Cache.KeyIgnoreQueryParams = site.NormalizeQueryKeys(item.Cache.KeyIgnoreQueryParams)
	item.Canary.Header = httpHeaderCanonical(item.Canary.Header)
	item.Canary.HeaderValue = strings.TrimSpace(item.Canary.HeaderValue)
	item.Canary.Cookie = strings.TrimSpace(item.Canary.Cookie)
	item.Canary.CookieValue = strings.TrimSpace(item.Canary.CookieValue)
	item.Canary.Upstream, item.Canary.Upstreams = site.NormalizeUpstreams(item.Canary.Upstream, item.Canary.Upstreams)
	for i := range item.Routes {
		item.Routes[i].Methods = site.NormalizeHTTPMethods(item.Routes[i].Methods)
		item.Routes[i].Header = httpHeaderCanonical(item.Routes[i].Header)
		item.Routes[i].HeaderValue = strings.TrimSpace(item.Routes[i].HeaderValue)
		item.Routes[i].Cookie = strings.TrimSpace(item.Routes[i].Cookie)
		item.Routes[i].CookieValue = strings.TrimSpace(item.Routes[i].CookieValue)
		item.Routes[i].Query = strings.TrimSpace(item.Routes[i].Query)
		item.Routes[i].QueryValue = strings.TrimSpace(item.Routes[i].QueryValue)
	}
	if item.Canary.LoadBalanceStrategy == "" {
		item.Canary.LoadBalanceStrategy = site.LoadBalanceRound
	}

	if !item.BasicAuth.Enabled {
		item.BasicAuth.Username = ""
		item.BasicAuth.Password = ""
		item.BasicAuth.PasswordHash = ""
	} else if item.BasicAuth.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(item.BasicAuth.Password), bcrypt.DefaultCost)
		if err != nil {
			return site.Site{}, fmt.Errorf("basicAuth password hash failed: %w", err)
		}
		item.BasicAuth.PasswordHash = string(hash)
		item.BasicAuth.Password = ""
	}

	if err := site.Validate(item); err != nil {
		return site.Site{}, err
	}
	return item, nil
}

func normalizeStringList(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		value := strings.TrimSpace(item)
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

func httpHeaderCanonical(name string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(name)), "-")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, "-")
}

func ensureSiteUniqueness(items []site.Site) error {
	domainOwner := map[string]string{}
	portOwner := map[int]string{}

	for _, item := range items {
		for _, domain := range site.AllDomains(item) {
			if owner, exists := domainOwner[domain]; exists {
				return fmt.Errorf("domain already exists: %s (used by %s and %s)", domain, owner, item.ID)
			}
			domainOwner[domain] = item.ID
		}

		if !item.Enabled || item.ListenPort <= 0 {
			continue
		}
		if owner, exists := portOwner[item.ListenPort]; exists {
			return fmt.Errorf("listen port already exists: %d (used by %s and %s)", item.ListenPort, owner, item.ID)
		}
		portOwner[item.ListenPort] = item.ID
	}
	return nil
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
