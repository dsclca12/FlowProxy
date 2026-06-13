package main

import (
	"sync"
	"time"

	"flowproxy/internal/alert"
	"flowproxy/internal/proxy"
	"flowproxy/internal/settings"
)

type alertDispatcher struct {
	mu       sync.Mutex
	notifier *alert.Notifier
}

func newAlertDispatcher(router *proxy.Router) *alertDispatcher {
	d := &alertDispatcher{}
	if router != nil {
		router.SetAlertHook(func(entry proxy.AccessLogEntry) {
			d.Record(entry)
		})
	}
	return d
}

func (d *alertDispatcher) Apply(cfg settings.Alert) {
	if d == nil {
		return
	}
	next := alert.New(alert.Options{
		WebhookURL:         cfg.WebhookURL,
		Consecutive5xx:     cfg.Consecutive5xx,
		LatencyThresholdMs: int64(cfg.LatencyMs),
		Cooldown:           parseAlertCooldown(cfg.Cooldown),
	})
	d.mu.Lock()
	prev := d.notifier
	d.notifier = next
	d.mu.Unlock()
	if prev != nil {
		prev.Close()
	}
}

func (d *alertDispatcher) Record(entry proxy.AccessLogEntry) {
	if d == nil {
		return
	}
	d.mu.Lock()
	notifier := d.notifier
	d.mu.Unlock()
	if notifier == nil {
		return
	}
	notifier.Record(alert.Event{
		Timestamp:  entry.Timestamp,
		SiteID:     entry.SiteID,
		Domain:     entry.Domain,
		ClientIP:   entry.ClientIP,
		Method:     entry.Method,
		Path:       entry.Path,
		StatusCode: entry.StatusCode,
		DurationMs: entry.DurationMs,
		Upstream:   entry.Upstream,
		Error:      entry.Error,
	})
}

func (d *alertDispatcher) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	notifier := d.notifier
	d.notifier = nil
	d.mu.Unlock()
	if notifier != nil {
		notifier.Close()
	}
}

func (d *alertDispatcher) Emit(kind string, payload map[string]any) {
	if d == nil {
		return
	}
	d.mu.Lock()
	notifier := d.notifier
	d.mu.Unlock()
	if notifier == nil {
		return
	}
	notifier.Emit(kind, payload)
}

func parseAlertCooldown(raw string) time.Duration {
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 5 * time.Minute
	}
	return d
}
