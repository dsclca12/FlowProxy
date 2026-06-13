package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flowproxy/internal/certmgr"
	"flowproxy/internal/settings"
	"flowproxy/internal/site"
)

func TestLoadFromFileApplyRuntimeAndWriteData(t *testing.T) {
	tmp := t.TempDir()
	dataFile := filepath.Join(tmp, "state", "sites.json")
	settingsFile := filepath.Join(tmp, "state", "settings.json")
	certDataFile := filepath.Join(tmp, "state", "certs.json")
	certDir := filepath.Join(tmp, "state", "certs")
	backupDir := filepath.Join(tmp, "state", "backups")

	raw := fmt.Sprintf(`
version: 1
runtime:
  adminAddr: ":19000"
  httpAddr: ":18080"
  httpsAddr: ":18443"
  dataFile: "%s"
  settingsFile: "%s"
  certDataFile: "%s"
  certDir: "%s"
  backupDir: "%s"
  accessLogFile: "%s"
  accessLogMaxRows: 4321
  accessLogTTL: "240h"
  accessLogFlushInterval: "3s"
  letsEncryptEmail: "ops@example.com"
  enableAutoTLS: true
  enableUI: false
  clusterSyncUrl: "https://leader-a.example.com/"
  clusterSyncUrls: ["https://leader-b.example.com/", "https://leader-a.example.com", " https://leader-c.example.com "]
settings:
  language: en
  webPort: 19000
  webAccess:
    allowCidrs: ["127.0.0.1"]
sites:
  - domain: "demo.example.com"
    certificateId: "cert-main"
    upstream: "http://127.0.0.1:3000"
    enabled: true
    forceHttps: true
    basicAuth:
      enabled: true
      username: "admin"
      password: "secret"
certificates:
  - id: "cert-main"
    type: "self_signed"
    domains: ["demo.example.com"]
`, dataFile, settingsFile, certDataFile, certDir, backupDir, filepath.Join(tmp, "state", "access-logs.json"))

	configPath := filepath.Join(tmp, "flowproxy.yaml")
	if err := os.WriteFile(configPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fileCfg, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}
	if fileCfg == nil || fileCfg.Runtime == nil || fileCfg.Sites == nil || fileCfg.Certificates == nil || fileCfg.Settings == nil {
		t.Fatalf("loaded config sections are incomplete: %#v", fileCfg)
	}

	loadedSite := (*fileCfg.Sites)[0]
	if loadedSite.ID == "" {
		t.Fatalf("site id should be auto-generated")
	}
	if loadedSite.BasicAuth.Password != "" {
		t.Fatalf("basic auth password should be stripped")
	}
	if loadedSite.BasicAuth.PasswordHash == "" {
		t.Fatalf("basic auth password hash should be generated")
	}

	runtime := Config{
		AdminAddr:        ":9000",
		HTTPAddr:         ":80",
		HTTPSAddr:        ":443",
		DataFile:         filepath.Join(tmp, "default", "sites.json"),
		SettingsFile:     filepath.Join(tmp, "default", "settings.json"),
		CertDataFile:     filepath.Join(tmp, "default", "certificates.json"),
		CertDir:          filepath.Join(tmp, "default", "certs"),
		BackupDir:        filepath.Join(tmp, "default", "backups"),
		AccessLogFile:    filepath.Join(tmp, "default", "access-logs.json"),
		AccessLogTTL:     24 * time.Hour,
		AccessLogFlush:   5 * time.Second,
		AccessLogMaxRows: 500,
		EnableAutoTLS:    false,
		EnableUI:         true,
	}
	if err := runtime.ApplyRuntimeFile(fileCfg.Runtime); err != nil {
		t.Fatalf("ApplyRuntimeFile() error = %v", err)
	}
	if runtime.AdminAddr != ":19000" || runtime.HTTPAddr != ":18080" || runtime.HTTPSAddr != ":18443" {
		t.Fatalf("runtime addresses not overridden: %+v", runtime)
	}
	if runtime.DataFile != dataFile || runtime.SettingsFile != settingsFile || runtime.CertDataFile != certDataFile || runtime.CertDir != certDir || runtime.BackupDir != backupDir {
		t.Fatalf("runtime file paths not overridden: %+v", runtime)
	}
	if runtime.AccessLogFile != filepath.Join(tmp, "state", "access-logs.json") {
		t.Fatalf("runtime accessLogFile not overridden: %+v", runtime)
	}
	if runtime.AccessLogMaxRows != 4321 {
		t.Fatalf("runtime accessLogMaxRows not overridden: %+v", runtime)
	}
	if runtime.AccessLogTTL != 240*time.Hour {
		t.Fatalf("runtime accessLogTTL not overridden: %+v", runtime)
	}
	if runtime.AccessLogFlush != 3*time.Second {
		t.Fatalf("runtime accessLogFlush not overridden: %+v", runtime)
	}
	if !runtime.EnableAutoTLS || runtime.EnableUI {
		t.Fatalf("runtime booleans not overridden: %+v", runtime)
	}
	if runtime.ClusterSyncURL != "https://leader-a.example.com" {
		t.Fatalf("unexpected runtime clusterSyncUrl: %q", runtime.ClusterSyncURL)
	}
	if len(runtime.ClusterSyncURLs) != 3 {
		t.Fatalf("unexpected runtime clusterSyncUrls: %#v", runtime.ClusterSyncURLs)
	}

	if err := ApplyDataFileConfig(runtime, fileCfg); err != nil {
		t.Fatalf("ApplyDataFileConfig() error = %v", err)
	}

	settingsData, err := os.ReadFile(runtime.SettingsFile)
	if err != nil {
		t.Fatalf("read settings file: %v", err)
	}
	var gotSettings settings.Settings
	if err := json.Unmarshal(settingsData, &gotSettings); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	if gotSettings.WebPort != 19000 || gotSettings.Language != "en" {
		t.Fatalf("unexpected settings: %+v", gotSettings)
	}

	sitesData, err := os.ReadFile(runtime.DataFile)
	if err != nil {
		t.Fatalf("read sites file: %v", err)
	}
	var gotSites []site.Site
	if err := json.Unmarshal(sitesData, &gotSites); err != nil {
		t.Fatalf("unmarshal sites: %v", err)
	}
	if len(gotSites) != 1 || gotSites[0].ID == "" || gotSites[0].Domain != "demo.example.com" {
		t.Fatalf("unexpected sites: %+v", gotSites)
	}

	certData, err := os.ReadFile(runtime.CertDataFile)
	if err != nil {
		t.Fatalf("read cert file: %v", err)
	}
	var gotCertModel struct {
		Certificates []certmgr.Certificate `json:"certificates"`
	}
	if err := json.Unmarshal(certData, &gotCertModel); err != nil {
		t.Fatalf("unmarshal cert model: %v", err)
	}
	if len(gotCertModel.Certificates) != 1 || gotCertModel.Certificates[0].ID != "cert-main" {
		t.Fatalf("unexpected certs: %+v", gotCertModel.Certificates)
	}
}

func TestLoadFromFileStrictUnknownField(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "flowproxy.yaml")
	raw := `
version: 1
runtime:
  adminAddr: ":9000"
  unknownField: "oops"
`
	if err := os.WriteFile(configPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadFromFile(configPath)
	if err == nil {
		t.Fatalf("expected error for unknown field")
	}
	if !strings.Contains(err.Error(), "unknownField") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadFromFileRejectsMissingCertificateReference(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "flowproxy.yaml")
	raw := `
version: 1
sites:
  - id: "site-a"
    domain: "demo.example.com"
    certificateId: "cert-not-found"
    upstream: "http://127.0.0.1:8080"
    enabled: true
certificates:
  - id: "cert-a"
    type: "self_signed"
    domains: ["demo.example.com"]
`
	if err := os.WriteFile(configPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadFromFile(configPath)
	if err == nil {
		t.Fatalf("expected certificate reference validation error")
	}
	if !strings.Contains(err.Error(), "certificateId") {
		t.Fatalf("unexpected error: %v", err)
	}
}
