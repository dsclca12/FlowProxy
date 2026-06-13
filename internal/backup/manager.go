package backup

import (
	"archive/zip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"flowproxy/internal/settings"
)

var ErrNotFound = errors.New("backup not found")

const idlePollInterval = 24 * time.Hour

type Options struct {
	BackupDir     string
	DataFile      string
	SettingsFile  string
	CertDataFile  string
	AdminAuthFile string
	AccessLogFile string
	CertDir       string
}

type Snapshot struct {
	Name      string    `json:"name"`
	SizeBytes int64     `json:"sizeBytes"`
	CreatedAt time.Time `json:"createdAt"`
}

type Status struct {
	ScheduleEnabled  bool       `json:"scheduleEnabled"`
	ScheduleInterval string     `json:"scheduleInterval"`
	KeepLast         int        `json:"keepLast"`
	LastSuccessAt    *time.Time `json:"lastSuccessAt,omitempty"`
	LastBackupName   string     `json:"lastBackupName,omitempty"`
	LastError        string     `json:"lastError,omitempty"`
}

type Manager struct {
	opts Options

	mu sync.RWMutex

	schedule        settings.Backup
	lastScheduledAt time.Time
	lastSuccessAt   time.Time
	lastBackupName  string
	lastError       string

	createMu sync.Mutex
	closeMu  sync.Once
	wakeCh   chan struct{}
	stopCh   chan struct{}
	doneCh   chan struct{}
}

var knownBackupEntries = []string{
	"meta.json",
	"data/sites.json",
	"data/settings.json",
	"data/certificates.json",
	"data/admin-auth.json",
	"data/access-logs.json",
}

func New(opts Options, initial settings.Backup) (*Manager, error) {
	if strings.TrimSpace(opts.BackupDir) == "" {
		return nil, errors.New("backup directory is required")
	}
	opts = cleanOptions(opts)

	m := &Manager{
		opts:   opts,
		wakeCh: make(chan struct{}, 1),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	if err := m.ApplySchedule(initial); err != nil {
		return nil, err
	}
	go m.loop()
	return m, nil
}

func (m *Manager) Close() {
	select {
	case <-m.doneCh:
		return
	default:
	}
	m.closeMu.Do(func() {
		close(m.stopCh)
	})
	<-m.doneCh
}

func (m *Manager) ApplySchedule(cfg settings.Backup) error {
	normalized, err := normalizeSchedule(cfg)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	m.mu.Lock()
	wasEnabled := m.schedule.Enabled
	m.schedule = normalized
	if normalized.Enabled && !wasEnabled {
		m.lastScheduledAt = now
	}
	if !normalized.Enabled {
		m.lastScheduledAt = time.Time{}
	}
	m.mu.Unlock()
	m.wake()
	return nil
}

func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := Status{
		ScheduleEnabled:  m.schedule.Enabled,
		ScheduleInterval: m.schedule.Interval,
		KeepLast:         m.schedule.KeepLast,
		LastBackupName:   m.lastBackupName,
		LastError:        m.lastError,
	}
	if !m.lastSuccessAt.IsZero() {
		t := m.lastSuccessAt
		out.LastSuccessAt = &t
	}
	return out
}

func (m *Manager) Create(trigger string) (Snapshot, error) {
	m.createMu.Lock()
	defer m.createMu.Unlock()

	keepLast := m.currentKeepLast()
	snapshot, err := m.createArchive(trigger)
	if err != nil {
		m.setLastError(err.Error())
		return Snapshot{}, err
	}
	if err := m.pruneOldBackups(keepLast); err != nil {
		m.setLastError(err.Error())
		return Snapshot{}, err
	}
	m.setLastSuccess(snapshot.Name)
	return snapshot, nil
}

func (m *Manager) Import(reader io.Reader, filename string) (Snapshot, error) {
	if reader == nil {
		return Snapshot{}, errors.New("backup reader is required")
	}

	m.createMu.Lock()
	defer m.createMu.Unlock()

	if err := os.MkdirAll(m.opts.BackupDir, 0o755); err != nil {
		m.setLastError(err.Error())
		return Snapshot{}, fmt.Errorf("create backup directory failed: %w", err)
	}

	base := sanitizeBackupBaseName(filename)
	if base == "" {
		base = "uploaded-backup"
	}

	now := time.Now().UTC()
	suffix, err := randomHex(3)
	if err != nil {
		m.setLastError(err.Error())
		return Snapshot{}, fmt.Errorf("generate backup filename failed: %w", err)
	}

	name := fmt.Sprintf("%s-%s-%s.zip", base, now.Format("20060102-150405"), suffix)
	finalPath := filepath.Join(m.opts.BackupDir, name)
	tmpPath := finalPath + ".tmp"

	out, err := os.Create(tmpPath)
	if err != nil {
		m.setLastError(err.Error())
		return Snapshot{}, err
	}
	if _, err := io.Copy(out, reader); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		m.setLastError(err.Error())
		return Snapshot{}, err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmpPath)
		m.setLastError(err.Error())
		return Snapshot{}, err
	}

	if err := validateImportedBackup(tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		m.setLastError(err.Error())
		return Snapshot{}, err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		m.setLastError(err.Error())
		return Snapshot{}, err
	}

	info, err := os.Stat(finalPath)
	if err != nil {
		m.setLastError(err.Error())
		return Snapshot{}, err
	}
	item := Snapshot{
		Name:      name,
		SizeBytes: info.Size(),
		CreatedAt: info.ModTime().UTC(),
	}

	if err := m.pruneOldBackups(m.currentKeepLast()); err != nil {
		m.setLastError(err.Error())
		return Snapshot{}, err
	}
	m.setLastSuccess(item.Name)
	return item, nil
}

func (m *Manager) List(limit int) ([]Snapshot, error) {
	if limit <= 0 {
		limit = 200
	}
	entries, err := os.ReadDir(m.opts.BackupDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Snapshot{}, nil
		}
		return nil, err
	}

	items := make([]Snapshot, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".zip") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		items = append(items, Snapshot{
			Name:      name,
			SizeBytes: info.Size(),
			CreatedAt: info.ModTime().UTC(),
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].Name > items[j].Name
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (m *Manager) Resolve(name string) (string, Snapshot, error) {
	cleaned := strings.TrimSpace(name)
	if cleaned == "" || cleaned != filepath.Base(cleaned) || !strings.HasSuffix(strings.ToLower(cleaned), ".zip") {
		return "", Snapshot{}, ErrNotFound
	}
	target := filepath.Join(m.opts.BackupDir, cleaned)
	info, err := os.Stat(target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", Snapshot{}, ErrNotFound
		}
		return "", Snapshot{}, err
	}
	if info.IsDir() {
		return "", Snapshot{}, ErrNotFound
	}
	return target, Snapshot{
		Name:      cleaned,
		SizeBytes: info.Size(),
		CreatedAt: info.ModTime().UTC(),
	}, nil
}

func (m *Manager) loop() {
	defer close(m.doneCh)

	for {
		wait := m.nextWaitDuration()
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
			if m.markScheduledRun() {
				if _, err := m.Create("scheduled"); err != nil {
					// Error state is already captured in Create().
				}
			}
		case <-m.wakeCh:
		case <-m.stopCh:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

func (m *Manager) nextWaitDuration() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.schedule.Enabled {
		return idlePollInterval
	}

	interval, err := time.ParseDuration(m.schedule.Interval)
	if err != nil || interval < time.Minute {
		return idlePollInterval
	}
	if m.lastScheduledAt.IsZero() {
		return interval
	}
	elapsed := time.Since(m.lastScheduledAt)
	if elapsed >= interval {
		return 0
	}
	return interval - elapsed
}

func (m *Manager) markScheduledRun() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.schedule.Enabled {
		return false
	}
	m.lastScheduledAt = time.Now().UTC()
	return true
}

func (m *Manager) wake() {
	select {
	case m.wakeCh <- struct{}{}:
	default:
	}
}

func (m *Manager) currentKeepLast() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.schedule.KeepLast < 1 {
		return 30
	}
	return m.schedule.KeepLast
}

func (m *Manager) setLastError(message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastError = strings.TrimSpace(message)
}

func (m *Manager) setLastSuccess(name string) {
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastSuccessAt = now
	m.lastBackupName = name
	m.lastError = ""
}

func (m *Manager) createArchive(trigger string) (Snapshot, error) {
	if err := os.MkdirAll(m.opts.BackupDir, 0o755); err != nil {
		return Snapshot{}, fmt.Errorf("create backup directory failed: %w", err)
	}

	now := time.Now().UTC()
	suffix, err := randomHex(3)
	if err != nil {
		return Snapshot{}, fmt.Errorf("generate backup filename failed: %w", err)
	}
	name := fmt.Sprintf("flowproxy-backup-%s-%s.zip", now.Format("20060102-150405"), suffix)
	finalPath := filepath.Join(m.opts.BackupDir, name)
	tmpPath := finalPath + ".tmp"

	file, err := os.Create(tmpPath)
	if err != nil {
		return Snapshot{}, err
	}

	zw := zip.NewWriter(file)
	if err := m.writeMetadata(zw, trigger, now); err != nil {
		_ = zw.Close()
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return Snapshot{}, err
	}

	if err := m.addFileIfExists(zw, m.opts.DataFile, "data/sites.json"); err != nil {
		_ = zw.Close()
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return Snapshot{}, err
	}
	if err := m.addFileIfExists(zw, m.opts.SettingsFile, "data/settings.json"); err != nil {
		_ = zw.Close()
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return Snapshot{}, err
	}
	if err := m.addFileIfExists(zw, m.opts.CertDataFile, "data/certificates.json"); err != nil {
		_ = zw.Close()
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return Snapshot{}, err
	}
	if err := m.addFileIfExists(zw, m.opts.AdminAuthFile, "data/admin-auth.json"); err != nil {
		_ = zw.Close()
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return Snapshot{}, err
	}
	if err := m.addFileIfExists(zw, m.opts.AccessLogFile, "data/access-logs.json"); err != nil {
		_ = zw.Close()
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return Snapshot{}, err
	}
	if err := m.addDirIfExists(zw, m.opts.CertDir, "data/certs"); err != nil {
		_ = zw.Close()
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return Snapshot{}, err
	}

	if err := zw.Close(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return Snapshot{}, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return Snapshot{}, err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return Snapshot{}, err
	}

	info, err := os.Stat(finalPath)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Name:      name,
		SizeBytes: info.Size(),
		CreatedAt: info.ModTime().UTC(),
	}, nil
}

func (m *Manager) writeMetadata(zw *zip.Writer, trigger string, now time.Time) error {
	payload := map[string]any{
		"createdAt": now.UTC().Format(time.RFC3339Nano),
		"trigger":   strings.TrimSpace(trigger),
		"version":   1,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	header := &zip.FileHeader{
		Name:     "meta.json",
		Method:   zip.Deflate,
		Modified: now,
	}
	w, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func (m *Manager) addFileIfExists(zw *zip.Writer, sourcePath string, archivePath string) error {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return nil
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.IsDir() {
		return nil
	}

	input, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer input.Close()

	header := &zip.FileHeader{
		Name:     filepath.ToSlash(filepath.Clean(archivePath)),
		Method:   zip.Deflate,
		Modified: info.ModTime(),
	}
	out, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, input)
	return err
}

func (m *Manager) addDirIfExists(zw *zip.Writer, sourceDir string, archivePrefix string) error {
	sourceDir = strings.TrimSpace(sourceDir)
	if sourceDir == "" {
		return nil
	}
	info, err := os.Stat(sourceDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return nil
	}

	return filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		archivePath := filepath.ToSlash(filepath.Join(archivePrefix, relPath))
		return m.addFileIfExists(zw, path, archivePath)
	})
}

func (m *Manager) pruneOldBackups(keepLast int) error {
	if keepLast < 1 {
		return nil
	}
	items, err := m.List(0)
	if err != nil {
		return err
	}
	if len(items) <= keepLast {
		return nil
	}
	for _, item := range items[keepLast:] {
		target := filepath.Join(m.opts.BackupDir, item.Name)
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func normalizeSchedule(input settings.Backup) (settings.Backup, error) {
	interval := strings.TrimSpace(input.Interval)
	if interval == "" {
		interval = "24h"
	}
	duration, err := time.ParseDuration(interval)
	if err != nil {
		return settings.Backup{}, fmt.Errorf("backup interval is invalid duration: %w", err)
	}
	if duration < time.Minute {
		return settings.Backup{}, errors.New("backup interval must be >= 1m")
	}

	keepLast := input.KeepLast
	if keepLast == 0 {
		keepLast = 30
	}
	if keepLast < 1 || keepLast > 1000 {
		return settings.Backup{}, errors.New("backup keepLast must be within 1-1000")
	}
	return settings.Backup{
		Enabled:  input.Enabled,
		Interval: interval,
		KeepLast: keepLast,
	}, nil
}

func cleanOptions(in Options) Options {
	in.BackupDir = filepath.Clean(in.BackupDir)
	in.DataFile = filepath.Clean(in.DataFile)
	in.SettingsFile = filepath.Clean(in.SettingsFile)
	in.CertDataFile = filepath.Clean(in.CertDataFile)
	in.AdminAuthFile = filepath.Clean(in.AdminAuthFile)
	in.AccessLogFile = filepath.Clean(in.AccessLogFile)
	in.CertDir = filepath.Clean(in.CertDir)
	return in
}

func randomHex(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func validateImportedBackup(path string) error {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("invalid backup zip: %w", err)
	}
	defer reader.Close()

	hasKnownEntry := false
	for _, file := range reader.File {
		name := strings.TrimSpace(filepath.ToSlash(file.Name))
		if name == "" {
			continue
		}
		if strings.HasPrefix(name, "/") || strings.Contains(name, "../") {
			return errors.New("invalid backup zip path")
		}
		for _, known := range knownBackupEntries {
			if name == known {
				hasKnownEntry = true
				break
			}
		}
		if strings.HasPrefix(name, "data/certs/") {
			hasKnownEntry = true
		}
	}
	if !hasKnownEntry {
		return errors.New("uploaded zip does not look like a flowproxy backup")
	}
	return nil
}

func sanitizeBackupBaseName(filename string) string {
	base := strings.TrimSpace(filepath.Base(filename))
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = strings.ToLower(base)
	var b strings.Builder
	b.Grow(len(base))
	for _, ch := range base {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch == '-' || ch == '_' || ch == '.':
			b.WriteRune(ch)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if out == "" {
		return ""
	}
	return out
}
