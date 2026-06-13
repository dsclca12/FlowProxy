package clustersync

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"flowproxy/internal/settings"
)

const (
	ModeController = "controller"
	ModeFollower   = "follower"
)

type CertificateSyncStatus struct {
	Enabled       bool      `json:"enabled"`
	LastSyncAt    time.Time `json:"lastSyncAt,omitempty"`
	LastFailureAt time.Time `json:"lastFailureAt,omitempty"`
	LastError     string    `json:"lastError,omitempty"`
	SyncedCount   int       `json:"syncedCount"`
}

type RuntimeStatus struct {
	Mode                string                `json:"mode"`
	ActiveEndpoint      string                `json:"activeEndpoint,omitempty"`
	ControlWritable     bool                  `json:"controlWritable"`
	SyncInterval        string                `json:"syncInterval"`
	LastAttemptAt       time.Time             `json:"lastAttemptAt,omitempty"`
	LastFetchAt         time.Time             `json:"lastFetchAt,omitempty"`
	LastApplyAt         time.Time             `json:"lastApplyAt,omitempty"`
	LastSuccessAt       time.Time             `json:"lastSuccessAt,omitempty"`
	LastFailureAt       time.Time             `json:"lastFailureAt,omitempty"`
	LastError           string                `json:"lastError,omitempty"`
	LastFailedStage     string                `json:"lastFailedStage,omitempty"`
	ConsecutiveFailures int                   `json:"consecutiveFailures"`
	FailCloseActive     bool                  `json:"failCloseActive"`
	FailCloseReason     string                `json:"failCloseReason,omitempty"`
	RetryAfterSeconds   int                   `json:"retryAfterSeconds,omitempty"`
	Config              settings.ClusterSync  `json:"config"`
	Certificate         CertificateSyncStatus `json:"certificate"`
}

type RuntimeState struct {
	mu sync.RWMutex

	mode         string
	syncInterval time.Duration
	config       settings.ClusterSync

	lastAttemptAt       time.Time
	lastFetchAt         time.Time
	lastApplyAt         time.Time
	lastSuccessAt       time.Time
	lastFailureAt       time.Time
	lastError           string
	lastFailedStage     string
	consecutiveFailures int

	certificate    CertificateSyncStatus
	activeEndpoint string
}

func NewRuntimeState(mode string, cfg settings.ClusterSync, syncInterval time.Duration) *RuntimeState {
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "" {
		m = ModeController
	}
	if syncInterval <= 0 {
		syncInterval = 3 * time.Second
	}
	return &RuntimeState{
		mode:         m,
		syncInterval: syncInterval,
		config:       cfg,
		certificate: CertificateSyncStatus{
			Enabled: cfg.CertificateSyncEnabled,
		},
	}
}

func (s *RuntimeState) SetMode(mode string) {
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "" {
		m = ModeController
	}
	s.mu.Lock()
	s.mode = m
	s.mu.Unlock()
}

func (s *RuntimeState) UpdateConfig(cfg settings.ClusterSync) {
	s.mu.Lock()
	s.config = cfg
	s.certificate.Enabled = cfg.CertificateSyncEnabled
	s.mu.Unlock()
}

func (s *RuntimeState) SetSyncInterval(interval time.Duration) {
	if interval <= 0 {
		return
	}
	s.mu.Lock()
	s.syncInterval = interval
	s.mu.Unlock()
}

func (s *RuntimeState) StartAttempt(now time.Time) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	s.lastAttemptAt = now.UTC()
	s.mu.Unlock()
}

func (s *RuntimeState) MarkFetchSuccess(now time.Time) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	s.lastFetchAt = now.UTC()
	s.mu.Unlock()
}

func (s *RuntimeState) MarkApplySuccess(now time.Time) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	s.lastApplyAt = now.UTC()
	s.mu.Unlock()
}

func (s *RuntimeState) MarkSuccess(now time.Time) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	s.lastSuccessAt = now.UTC()
	s.lastError = ""
	s.lastFailedStage = ""
	s.consecutiveFailures = 0
	s.mu.Unlock()
}

func (s *RuntimeState) MarkFailure(stage string, err error, now time.Time) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	message := ""
	if err != nil {
		message = strings.TrimSpace(err.Error())
	}
	stage = strings.TrimSpace(stage)
	if stage == "" {
		stage = "sync"
	}
	s.mu.Lock()
	s.lastFailureAt = now.UTC()
	s.lastFailedStage = stage
	s.lastError = message
	s.consecutiveFailures++
	s.mu.Unlock()
}

func (s *RuntimeState) MarkCertificateSyncSuccess(count int, now time.Time) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if count < 0 {
		count = 0
	}
	s.mu.Lock()
	s.certificate.LastSyncAt = now.UTC()
	s.certificate.LastError = ""
	s.certificate.SyncedCount = count
	s.mu.Unlock()
}

func (s *RuntimeState) MarkCertificateSyncFailure(err error, now time.Time) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	message := ""
	if err != nil {
		message = strings.TrimSpace(err.Error())
	}
	s.mu.Lock()
	s.certificate.LastFailureAt = now.UTC()
	s.certificate.LastError = message
	s.mu.Unlock()
}

func (s *RuntimeState) SetActiveEndpoint(endpoint string) {
	s.mu.Lock()
	s.activeEndpoint = strings.TrimSpace(endpoint)
	s.mu.Unlock()
}

func (s *RuntimeState) Snapshot(now time.Time) RuntimeStatus {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.RLock()
	out := RuntimeStatus{
		Mode:                s.mode,
		ActiveEndpoint:      s.activeEndpoint,
		SyncInterval:        s.syncInterval.String(),
		LastAttemptAt:       s.lastAttemptAt,
		LastFetchAt:         s.lastFetchAt,
		LastApplyAt:         s.lastApplyAt,
		LastSuccessAt:       s.lastSuccessAt,
		LastFailureAt:       s.lastFailureAt,
		LastError:           s.lastError,
		LastFailedStage:     s.lastFailedStage,
		ConsecutiveFailures: s.consecutiveFailures,
		Config:              s.config,
		Certificate:         s.certificate,
	}
	s.mu.RUnlock()
	active, reason, retryAfter := shouldFailClose(out, now)
	out.FailCloseActive = active
	out.FailCloseReason = reason
	out.RetryAfterSeconds = retryAfter
	return out
}

func (s *RuntimeState) FailCloseStatus(now time.Time) (bool, int) {
	snapshot := s.Snapshot(now)
	return snapshot.FailCloseActive, snapshot.RetryAfterSeconds
}

func shouldFailClose(status RuntimeStatus, now time.Time) (bool, string, int) {
	if status.Mode != ModeFollower {
		return false, "", 0
	}
	if !status.Config.FailCloseEnabled {
		return false, "", 0
	}

	threshold := status.Config.FailCloseConsecutiveFailures
	if threshold <= 0 {
		threshold = 10
	}
	if status.ConsecutiveFailures >= threshold {
		return true, "consecutive_failures", defaultRetryAfter(status.SyncInterval)
	}

	staleAfter := strings.TrimSpace(status.Config.FailCloseStaleAfter)
	if staleAfter == "" {
		staleAfter = "5m"
	}
	d, err := time.ParseDuration(staleAfter)
	if err != nil || d <= 0 {
		d = 5 * time.Minute
	}
	if status.LastFailureAt.IsZero() {
		return false, "", 0
	}
	if status.LastSuccessAt.IsZero() {
		if status.LastAttemptAt.IsZero() {
			return false, "", 0
		}
		if now.UTC().Sub(status.LastAttemptAt.UTC()) > d {
			return true, "stale_sync", defaultRetryAfter(status.SyncInterval)
		}
		return false, "", 0
	}
	if now.UTC().Sub(status.LastSuccessAt.UTC()) > d {
		return true, "stale_sync", defaultRetryAfter(status.SyncInterval)
	}
	return false, "", 0
}

func defaultRetryAfter(syncIntervalRaw string) int {
	d, err := time.ParseDuration(strings.TrimSpace(syncIntervalRaw))
	if err != nil || d <= 0 {
		d = 3 * time.Second
	}
	seconds := int(d.Seconds())
	if seconds < 3 {
		seconds = 3
	}
	if seconds > 30 {
		seconds = 30
	}
	return seconds
}

func (s RuntimeStatus) String() string {
	return fmt.Sprintf("mode=%s failClose=%t failures=%d lastError=%q", s.Mode, s.FailCloseActive, s.ConsecutiveFailures, s.LastError)
}
