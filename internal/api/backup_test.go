package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flowproxy/internal/backup"
	"flowproxy/internal/settings"
)

func TestHandleSettingsPartialUpdateKeepsBackupConfig(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "settings.json")
	settingsStore, err := settings.New(filePath, settings.Settings{Language: "zh", WebPort: 9000})
	if err != nil {
		t.Fatalf("new settings store: %v", err)
	}
	_, err = settingsStore.Update(settings.Settings{
		Language: "zh",
		WebPort:  9000,
		Backup: settings.Backup{
			Enabled:  true,
			Interval: "12h",
			KeepLast: 5,
		},
	})
	if err != nil {
		t.Fatalf("init backup settings failed: %v", err)
	}

	server := &Server{settingsStore: settingsStore}
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"language":"en"}`))
	rec := httptest.NewRecorder()
	server.handleSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	got := settingsStore.Get()
	if got.Language != "en" {
		t.Fatalf("unexpected language: %+v", got)
	}
	if !got.Backup.Enabled || got.Backup.Interval != "12h" || got.Backup.KeepLast != 5 {
		t.Fatalf("backup settings should be kept, got: %+v", got.Backup)
	}
}

func TestHandleSettingsPartialUpdateKeepsIPCountryAutoUpdates(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "settings.json")
	settingsStore, err := settings.New(filePath, settings.Settings{
		Language: "zh",
		WebPort:  9000,
		IPRuleSets: []settings.IPRuleSet{
			{ID: "office"},
		},
		IPCountryAutoUpdates: []settings.IPCountryAutoUpdate{
			{
				ID:        "cn-office",
				Enabled:   true,
				RuleSetID: "office",
				List:      "allow",
				Countries: []string{"CN"},
				Interval:  "24h",
				Source:    "ipdeny",
				CIDRs:     []string{"1.0.1.0/24"},
			},
		},
	})
	if err != nil {
		t.Fatalf("new settings store: %v", err)
	}

	server := &Server{settingsStore: settingsStore}
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"webAccess":{"allowCidrs":["127.0.0.1"]}}`))
	rec := httptest.NewRecorder()
	server.handleSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	got := settingsStore.Get()
	if len(got.IPCountryAutoUpdates) != 1 {
		t.Fatalf("ipCountryAutoUpdates should be kept, got: %+v", got.IPCountryAutoUpdates)
	}
	if got.IPCountryAutoUpdates[0].ID != "cn-office" {
		t.Fatalf("unexpected auto update task: %+v", got.IPCountryAutoUpdates[0])
	}
}

func TestHandleSettingsPartialUpdateKeepsIPRuleSourceOrder(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "settings.json")
	settingsStore, err := settings.New(filePath, settings.Settings{
		Language:          "zh",
		WebPort:           9000,
		IPRuleSourceOrder: []string{"country", "custom", "site"},
	})
	if err != nil {
		t.Fatalf("new settings store: %v", err)
	}

	server := &Server{settingsStore: settingsStore}
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"webAccess":{"allowCidrs":["127.0.0.1"]}}`))
	rec := httptest.NewRecorder()
	server.handleSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	got := settingsStore.Get()
	if len(got.IPRuleSourceOrder) != 3 || got.IPRuleSourceOrder[0] != "country" || got.IPRuleSourceOrder[1] != "custom" || got.IPRuleSourceOrder[2] != "site" {
		t.Fatalf("ipRuleSourceOrder should be kept, got: %#v", got.IPRuleSourceOrder)
	}
}

func TestHandleSettingsUpdatePreservesIPCountryAutoRuntimeFields(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "settings.json")
	attemptAt := time.Date(2026, 4, 18, 10, 0, 0, 0, time.UTC)
	syncAt := attemptAt.Add(-5 * time.Minute)
	settingsStore, err := settings.New(filePath, settings.Settings{
		Language: "zh",
		WebPort:  9000,
		IPRuleSets: []settings.IPRuleSet{
			{ID: "office"},
		},
		IPCountryAutoUpdates: []settings.IPCountryAutoUpdate{
			{
				ID:            "cn-office",
				Enabled:       true,
				RuleSetID:     "office",
				List:          "allow",
				Countries:     []string{"CN"},
				Interval:      "24h",
				Source:        "ipdeny",
				CIDRs:         []string{"1.0.1.0/24"},
				LastAttemptAt: attemptAt,
				LastSyncAt:    syncAt,
				LastError:     "test error",
			},
		},
	})
	if err != nil {
		t.Fatalf("new settings store: %v", err)
	}

	server := &Server{settingsStore: settingsStore}
	reqBody := `{
		"ipRuleSets":[{"id":"office","name":"Office"}],
		"ipCountryAutoUpdates":[
			{"id":"cn-office","enabled":true,"ruleSetId":"office","list":"allow","countries":["CN"],"interval":"12h","source":"ipdeny"}
		]
	}`
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()
	server.handleSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	got := settingsStore.Get()
	if len(got.IPCountryAutoUpdates) != 1 {
		t.Fatalf("unexpected ipCountryAutoUpdates: %+v", got.IPCountryAutoUpdates)
	}
	item := got.IPCountryAutoUpdates[0]
	if len(item.CIDRs) != 1 || item.CIDRs[0] != "1.0.1.0/24" {
		t.Fatalf("expected CIDRs preserved, got: %#v", item.CIDRs)
	}
	if !item.LastAttemptAt.Equal(attemptAt) || !item.LastSyncAt.Equal(syncAt) {
		t.Fatalf("expected runtime timestamps preserved, got: %+v", item)
	}
	if item.LastError != "test error" {
		t.Fatalf("expected lastError preserved, got: %s", item.LastError)
	}
	if item.Interval != "12h" {
		t.Fatalf("expected interval updated, got: %s", item.Interval)
	}
}

func TestHandleSettingsUpdateAcceptsEmptyIPCountryRuntimeTimeStrings(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "settings.json")
	settingsStore, err := settings.New(filePath, settings.Settings{
		Language: "zh",
		WebPort:  9000,
		IPRuleSets: []settings.IPRuleSet{
			{ID: "office"},
		},
	})
	if err != nil {
		t.Fatalf("new settings store: %v", err)
	}

	server := &Server{settingsStore: settingsStore}
	reqBody := `{
		"ipRuleSets":[{"id":"office","name":"Office"}],
		"ipCountryAutoUpdates":[
			{"id":"cn-office","enabled":true,"ruleSetId":"office","list":"allow","countries":["CN"],"interval":"24h","source":"ipdeny","lastAttemptAt":"","lastSyncAt":""}
		]
	}`
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()
	server.handleSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	got := settingsStore.Get()
	if len(got.IPCountryAutoUpdates) != 1 {
		t.Fatalf("unexpected ipCountryAutoUpdates: %+v", got.IPCountryAutoUpdates)
	}
	if got.IPCountryAutoUpdates[0].ID != "cn-office" {
		t.Fatalf("unexpected auto update task: %+v", got.IPCountryAutoUpdates[0])
	}
}

func TestHandleSettingsUpdateStripsUserProvidedIPCountryRuntimeFields(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "settings.json")
	attemptAt := time.Date(2026, 4, 18, 10, 0, 0, 0, time.UTC)
	syncAt := attemptAt.Add(-5 * time.Minute)
	settingsStore, err := settings.New(filePath, settings.Settings{
		Language: "zh",
		WebPort:  9000,
		IPRuleSets: []settings.IPRuleSet{
			{ID: "office"},
			{ID: "home"},
		},
		IPCountryAutoUpdates: []settings.IPCountryAutoUpdate{
			{
				ID:            "cn-office",
				Enabled:       true,
				RuleSetID:     "office",
				List:          "allow",
				Countries:     []string{"CN"},
				Interval:      "24h",
				Source:        "ipdeny",
				CIDRs:         []string{"1.0.1.0/24"},
				LastAttemptAt: attemptAt,
				LastSyncAt:    syncAt,
				LastError:     "old error",
			},
		},
	})
	if err != nil {
		t.Fatalf("new settings store: %v", err)
	}

	server := &Server{settingsStore: settingsStore}
	reqBody := `{
		"ipRuleSets":[{"id":"office"},{"id":"home"}],
		"ipCountryAutoUpdates":[
			{"id":"cn-office","enabled":true,"ruleSetId":"office","list":"allow","countries":["CN"],"interval":"12h","source":"ipdeny","cidrs":["9.9.9.0/24"],"lastAttemptAt":"2026-04-18T11:00:00Z","lastSyncAt":"2026-04-18T11:05:00Z","lastError":"new error"},
			{"id":"us-home","enabled":true,"ruleSetId":"home","list":"allow","countries":["US"],"interval":"24h","source":"ipdeny","cidrs":["8.8.8.0/24"],"lastAttemptAt":"2026-04-18T11:00:00Z","lastSyncAt":"2026-04-18T11:05:00Z","lastError":"should be stripped"}
		]
	}`
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()
	server.handleSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	got := settingsStore.Get()
	if len(got.IPCountryAutoUpdates) != 2 {
		t.Fatalf("unexpected ipCountryAutoUpdates: %+v", got.IPCountryAutoUpdates)
	}

	first := got.IPCountryAutoUpdates[0]
	if first.ID != "cn-office" {
		t.Fatalf("unexpected first task: %+v", first)
	}
	if len(first.CIDRs) != 1 || first.CIDRs[0] != "1.0.1.0/24" {
		t.Fatalf("existing runtime cidrs should be preserved: %#v", first.CIDRs)
	}
	if !first.LastAttemptAt.Equal(attemptAt) || !first.LastSyncAt.Equal(syncAt) || first.LastError != "old error" {
		t.Fatalf("existing runtime fields should be preserved: %+v", first)
	}

	second := got.IPCountryAutoUpdates[1]
	if second.ID != "us-home" {
		t.Fatalf("unexpected second task: %+v", second)
	}
	if len(second.CIDRs) != 0 || !second.LastAttemptAt.IsZero() || !second.LastSyncAt.IsZero() || second.LastError != "" {
		t.Fatalf("user-provided runtime fields must be stripped: %+v", second)
	}
}

func TestHandleBackupsCreateAndDownload(t *testing.T) {
	root := t.TempDir()
	opts := backup.Options{
		BackupDir:     filepath.Join(root, "backups"),
		DataFile:      filepath.Join(root, "data", "sites.json"),
		SettingsFile:  filepath.Join(root, "data", "settings.json"),
		CertDataFile:  filepath.Join(root, "data", "certificates.json"),
		AdminAuthFile: filepath.Join(root, "data", "admin-auth.json"),
		AccessLogFile: filepath.Join(root, "data", "access-logs.json"),
		CertDir:       filepath.Join(root, "data", "certs"),
	}
	if err := writeFile(opts.DataFile, `[]`); err != nil {
		t.Fatalf("write sites file: %v", err)
	}
	if err := writeFile(opts.SettingsFile, `{"language":"zh","webPort":9000}`); err != nil {
		t.Fatalf("write settings file: %v", err)
	}

	mgr, err := backup.New(opts, settings.Backup{Enabled: false, Interval: "24h", KeepLast: 10})
	if err != nil {
		t.Fatalf("new backup manager: %v", err)
	}
	defer mgr.Close()

	server := &Server{backupMgr: mgr}

	createReq := httptest.NewRequest(http.MethodPost, "/api/backups", nil)
	createRec := httptest.NewRecorder()
	server.handleBackups(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}

	var item backup.Snapshot
	if err := json.Unmarshal(createRec.Body.Bytes(), &item); err != nil {
		t.Fatalf("decode backup item failed: %v", err)
	}
	if item.Name == "" {
		t.Fatalf("backup name is empty")
	}

	downloadReq := httptest.NewRequest(http.MethodGet, "/api/backups/"+item.Name+"/download", nil)
	downloadRec := httptest.NewRecorder()
	server.handleBackupByID(downloadRec, downloadReq)
	if downloadRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", downloadRec.Code, downloadRec.Body.String())
	}
	if ct := downloadRec.Header().Get("Content-Type"); !strings.Contains(ct, "zip") {
		t.Fatalf("unexpected content-type: %s", ct)
	}

	quickReq := httptest.NewRequest(http.MethodGet, "/api/backups/download", nil)
	quickRec := httptest.NewRecorder()
	server.handleBackupQuickDownload(quickRec, quickReq)
	if quickRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for quick download, got %d: %s", quickRec.Code, quickRec.Body.String())
	}
	if ct := quickRec.Header().Get("Content-Type"); !strings.Contains(ct, "zip") {
		t.Fatalf("unexpected quick download content-type: %s", ct)
	}
}

func TestHandleBackupUpload(t *testing.T) {
	root := t.TempDir()
	opts := backup.Options{
		BackupDir:     filepath.Join(root, "backups"),
		DataFile:      filepath.Join(root, "data", "sites.json"),
		SettingsFile:  filepath.Join(root, "data", "settings.json"),
		CertDataFile:  filepath.Join(root, "data", "certificates.json"),
		AdminAuthFile: filepath.Join(root, "data", "admin-auth.json"),
		AccessLogFile: filepath.Join(root, "data", "access-logs.json"),
		CertDir:       filepath.Join(root, "data", "certs"),
	}
	mgr, err := backup.New(opts, settings.Backup{Enabled: false, Interval: "24h", KeepLast: 10})
	if err != nil {
		t.Fatalf("new backup manager: %v", err)
	}
	defer mgr.Close()
	server := &Server{backupMgr: mgr}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "upload.zip")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write(createBackupZipForUpload(t)); err != nil {
		t.Fatalf("write upload zip: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/backups/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	server.handleBackupUpload(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	items, err := mgr.List(10)
	if err != nil {
		t.Fatalf("list backup failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 imported backup, got %d", len(items))
	}
}

func writeFile(path string, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func createBackupZipForUpload(t *testing.T) []byte {
	t.Helper()
	buf := bytes.NewBuffer(nil)
	zw := zip.NewWriter(buf)
	entries := map[string]string{
		"meta.json":          `{"version":1}`,
		"data/sites.json":    `[]`,
		"data/settings.json": `{"language":"zh","webPort":9000}`,
	}
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}
