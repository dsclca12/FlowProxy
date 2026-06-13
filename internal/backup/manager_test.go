package backup

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"flowproxy/internal/settings"
)

func TestManagerCreateIncludesDataFiles(t *testing.T) {
	dir := t.TempDir()
	opts := testBackupOptions(dir)

	if err := os.MkdirAll(opts.CertDir, 0o755); err != nil {
		t.Fatalf("mkdir cert dir: %v", err)
	}
	mustWriteFile(t, opts.DataFile, `{"sites":[]}`)
	mustWriteFile(t, opts.SettingsFile, `{"language":"zh","webPort":9000}`)
	mustWriteFile(t, opts.CertDataFile, `{"certificates":[]}`)
	mustWriteFile(t, opts.AdminAuthFile, `{"username":"admin"}`)
	mustWriteFile(t, opts.AccessLogFile, `[]`)
	mustWriteFile(t, filepath.Join(opts.CertDir, "example.pem"), `CERT`)

	mgr, err := New(opts, settings.Backup{Enabled: false, Interval: "24h", KeepLast: 10})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Close()

	snapshot, err := mgr.Create("manual")
	if err != nil {
		t.Fatalf("create backup: %v", err)
	}
	if snapshot.Name == "" || snapshot.SizeBytes <= 0 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}

	archivePath, _, err := mgr.Resolve(snapshot.Name)
	if err != nil {
		t.Fatalf("resolve backup: %v", err)
	}
	checkZipContains(t, archivePath, []string{
		"meta.json",
		"data/sites.json",
		"data/settings.json",
		"data/certificates.json",
		"data/admin-auth.json",
		"data/access-logs.json",
		"data/certs/example.pem",
	})
}

func TestManagerCreatePrunesOldBackups(t *testing.T) {
	dir := t.TempDir()
	opts := testBackupOptions(dir)
	mustWriteFile(t, opts.DataFile, `{"sites":[]}`)
	mustWriteFile(t, opts.SettingsFile, `{"language":"zh","webPort":9000}`)

	mgr, err := New(opts, settings.Backup{Enabled: false, Interval: "24h", KeepLast: 2})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Close()

	for i := 0; i < 3; i++ {
		if _, err := mgr.Create("manual"); err != nil {
			t.Fatalf("create backup %d: %v", i, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	items, err := mgr.List(100)
	if err != nil {
		t.Fatalf("list backups: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 backups after prune, got %d", len(items))
	}
}

func TestManagerResolveRejectsInvalidName(t *testing.T) {
	dir := t.TempDir()
	opts := testBackupOptions(dir)
	mgr, err := New(opts, settings.Backup{Enabled: false, Interval: "24h", KeepLast: 5})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Close()

	if _, _, err := mgr.Resolve("../xx.zip"); err == nil {
		t.Fatalf("expected invalid name error")
	}
}

func TestManagerImportBackupZip(t *testing.T) {
	dir := t.TempDir()
	opts := testBackupOptions(dir)
	mgr, err := New(opts, settings.Backup{Enabled: false, Interval: "24h", KeepLast: 5})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Close()

	data := createTestBackupZip(t)
	item, err := mgr.Import(bytes.NewReader(data), "my-backup.zip")
	if err != nil {
		t.Fatalf("import backup: %v", err)
	}
	if item.Name == "" || item.SizeBytes <= 0 {
		t.Fatalf("unexpected imported item: %+v", item)
	}

	items, err := mgr.List(10)
	if err != nil {
		t.Fatalf("list backups: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 backup, got %d", len(items))
	}
}

func testBackupOptions(root string) Options {
	return Options{
		BackupDir:     filepath.Join(root, "backups"),
		DataFile:      filepath.Join(root, "data", "sites.json"),
		SettingsFile:  filepath.Join(root, "data", "settings.json"),
		CertDataFile:  filepath.Join(root, "data", "certs.json"),
		AdminAuthFile: filepath.Join(root, "data", "admin-auth.json"),
		AccessLogFile: filepath.Join(root, "data", "access-logs.json"),
		CertDir:       filepath.Join(root, "data", "certs"),
	}
}

func mustWriteFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func checkZipContains(t *testing.T, archivePath string, expected []string) {
	t.Helper()
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer reader.Close()

	seen := map[string]struct{}{}
	for _, file := range reader.File {
		seen[file.Name] = struct{}{}
	}
	for _, name := range expected {
		if _, ok := seen[name]; !ok {
			t.Fatalf("expected zip to contain %s", name)
		}
	}
}

func createTestBackupZip(t *testing.T) []byte {
	t.Helper()
	buf := bytes.NewBuffer(nil)
	zw := zip.NewWriter(buf)
	files := map[string]string{
		"meta.json":          `{"version":1}`,
		"data/sites.json":    `[]`,
		"data/settings.json": `{"language":"zh","webPort":9000}`,
	}
	for name, content := range files {
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
