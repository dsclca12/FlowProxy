package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultAccessLogMaxRows   = 10000
	defaultAccessLogFlushWait = 2 * time.Second
)

type AccessLogQuery struct {
	Limit     int
	From      *time.Time
	To        *time.Time
	SiteID    string
	Domain    string
	StatusMin int
	StatusMax int
}

type AccessLogStoreOptions struct {
	MaxRows      int
	RetentionTTL time.Duration
	FlushEvery   time.Duration
}

type AccessLogStore struct {
	mu           sync.RWMutex
	filePath     string
	maxRows      int
	retentionTTL time.Duration
	flushEvery   time.Duration
	logs         []AccessLogEntry
	dirty        bool
	closed       bool

	done chan struct{}
	stop chan struct{}
}

type accessLogPersistModel struct {
	Logs []AccessLogEntry `json:"logs"`
}

func NewAccessLogStore(filePath string, opts AccessLogStoreOptions) (*AccessLogStore, error) {
	path := strings.TrimSpace(filePath)
	if path == "" {
		return nil, errors.New("access log file path is empty")
	}

	maxRows := opts.MaxRows
	if maxRows <= 0 {
		maxRows = defaultAccessLogMaxRows
	}

	flushEvery := opts.FlushEvery
	if flushEvery <= 0 {
		flushEvery = defaultAccessLogFlushWait
	}

	s := &AccessLogStore{
		filePath:     filepath.Clean(path),
		maxRows:      maxRows,
		retentionTTL: opts.RetentionTTL,
		flushEvery:   flushEvery,
		logs:         []AccessLogEntry{},
		done:         make(chan struct{}),
		stop:         make(chan struct{}),
	}
	if err := s.load(); err != nil {
		return nil, err
	}

	go s.runFlusher()
	return s, nil
}

func (s *AccessLogStore) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.stop)
	s.mu.Unlock()

	<-s.done
	return nil
}

func (s *AccessLogStore) Append(entry AccessLogEntry) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.logs = append(s.logs, entry)
	s.pruneLocked(time.Now().UTC())
	s.dirty = true
	s.mu.Unlock()
}

func (s *AccessLogStore) Query(filter AccessLogQuery) []AccessLogEntry {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}

	statusMin := filter.StatusMin
	statusMax := filter.StatusMax
	if statusMin <= 0 {
		statusMin = 0
	}
	if statusMax <= 0 {
		statusMax = 999
	}

	siteID := strings.TrimSpace(filter.SiteID)
	domain := strings.TrimSpace(filter.Domain)

	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.logs) == 0 {
		return []AccessLogEntry{}
	}

	out := make([]AccessLogEntry, 0, minInt(limit, len(s.logs)))
	for i := len(s.logs) - 1; i >= 0 && len(out) < limit; i-- {
		entry := s.logs[i]
		if !matchAccessLog(entry, filter.From, filter.To, siteID, domain, statusMin, statusMax) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func (s *AccessLogStore) runFlusher() {
	ticker := time.NewTicker(s.flushEvery)
	defer func() {
		ticker.Stop()
		_ = s.flush()
		close(s.done)
	}()

	for {
		select {
		case <-ticker.C:
			_ = s.flush()
		case <-s.stop:
			return
		}
	}
}

func (s *AccessLogStore) load() error {
	if _, err := os.Stat(s.filePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}

	var model accessLogPersistModel
	if err := json.Unmarshal(data, &model); err != nil {
		var plain []AccessLogEntry
		if err2 := json.Unmarshal(data, &plain); err2 != nil {
			return err
		}
		model.Logs = plain
	}

	s.mu.Lock()
	s.logs = append([]AccessLogEntry{}, model.Logs...)
	prev := len(s.logs)
	s.pruneLocked(time.Now().UTC())
	s.dirty = len(s.logs) != prev
	needsFlush := s.dirty
	s.mu.Unlock()

	if needsFlush {
		_ = s.flush()
	}
	return nil
}

func (s *AccessLogStore) flush() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	snapshot := append([]AccessLogEntry{}, s.logs...)
	s.dirty = false
	s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.filePath), 0o755); err != nil {
		s.markDirty()
		return err
	}

	// Use streaming JSON encoder for better memory efficiency
	var buf bytes.Buffer
	buf.WriteByte('{')
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)

	buf.WriteString(`"logs":`)
	if err := enc.Encode(snapshot); err != nil {
		s.markDirty()
		return err
	}
	buf.WriteByte('}')

	// Atomic write: write to temp file, then rename
	tmpPath := s.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, buf.Bytes(), 0o644); err != nil {
		s.markDirty()
		return err
	}
	if err := os.Rename(tmpPath, s.filePath); err != nil {
		s.markDirty()
		os.Remove(tmpPath)
		return err
	}
	return nil
}

func (s *AccessLogStore) markDirty() {
	s.mu.Lock()
	if !s.closed {
		s.dirty = true
	}
	s.mu.Unlock()
}

func (s *AccessLogStore) pruneLocked(now time.Time) {
	if s.retentionTTL > 0 {
		cutoff := now.Add(-s.retentionTTL)
		start := 0
		for start < len(s.logs) && s.logs[start].Timestamp.Before(cutoff) {
			start++
		}
		if start > 0 {
			s.logs = append([]AccessLogEntry{}, s.logs[start:]...)
		}
	}
	if len(s.logs) > s.maxRows {
		s.logs = append([]AccessLogEntry{}, s.logs[len(s.logs)-s.maxRows:]...)
	}
}

func matchAccessLog(
	entry AccessLogEntry,
	from *time.Time,
	to *time.Time,
	siteID string,
	domain string,
	statusMin int,
	statusMax int,
) bool {
	if from != nil && entry.Timestamp.Before(*from) {
		return false
	}
	if to != nil && entry.Timestamp.After(*to) {
		return false
	}
	if siteID != "" && entry.SiteID != siteID {
		return false
	}
	if domain != "" && !strings.EqualFold(entry.Domain, domain) {
		return false
	}
	if entry.StatusCode < statusMin || entry.StatusCode > statusMax {
		return false
	}
	return true
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
