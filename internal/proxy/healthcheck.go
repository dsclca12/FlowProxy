package proxy

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"time"
)

func (c *compiledSite) healthTargets() []*upstreamTarget {
	if c == nil {
		return nil
	}
	seen := map[*upstreamTarget]struct{}{}
	out := make([]*upstreamTarget, 0)
	appendPool := func(pool *upstreamPool) {
		if pool == nil {
			return
		}
		for _, target := range pool.targets {
			if target == nil || !target.health.enabled {
				continue
			}
			if _, ok := seen[target]; ok {
				continue
			}
			seen[target] = struct{}{}
			out = append(out, target)
		}
	}
	appendPool(c.defaultPool)
	if c.canary != nil {
		appendPool(c.canary.pool)
	}
	for _, route := range c.routes {
		appendPool(route.pool)
	}
	return out
}

func (r *Router) startHealthChecks(targets []*upstreamTarget) {
	seen := map[*upstreamTarget]struct{}{}
	filtered := make([]*upstreamTarget, 0, len(targets))
	for _, target := range targets {
		if target == nil || !target.health.enabled {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		filtered = append(filtered, target)
	}
	if len(filtered) == 0 {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	if r.healthCancel != nil {
		r.healthCancel()
	}
	r.healthCancel = cancel
	r.mu.Unlock()

	// Single unified health checker goroutine for all targets
	go r.unifiedHealthCheckLoop(ctx, filtered)
}

// unifiedHealthCheckLoop runs health checks for all targets in a single goroutine.
// Each target tracks its last check time to respect per-target intervals.
func (r *Router) unifiedHealthCheckLoop(ctx context.Context, targets []*upstreamTarget) {
	// Determine minimum check interval across all targets
	minInterval := 10 * time.Second
	type targetState struct {
		target      *upstreamTarget
		interval    time.Duration
		lastChecked time.Time
		first       bool
	}
	states := make([]*targetState, 0, len(targets))
	for _, t := range targets {
		interval := t.health.interval
		if interval <= 0 {
			interval = 10 * time.Second
		}
		if interval < minInterval {
			minInterval = interval
		}
		states = append(states, &targetState{
			target:   t,
			interval: interval,
			first:    true,
		})
	}
	// Use a ticker at the minimum interval for timely checks
	ticker := time.NewTicker(minInterval)
	defer ticker.Stop()

	checkTarget := func(state *targetState) {
		t := state.target
		healthURL := *t.url
		healthURL.Path = t.health.path
		healthURL.RawPath = ""
		healthURL.RawQuery = ""
		r.performHealthCheck(ctx, t, &healthURL)
	}

	// Initial health checks
	for _, state := range states {
		checkTarget(state)
		state.lastChecked = time.Now()
		state.first = false
	}

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			for _, state := range states {
				if state.first || now.Sub(state.lastChecked) >= state.interval {
					checkTarget(state)
					state.lastChecked = now
					state.first = false
				}
			}
		}
	}
}

func (r *Router) performHealthCheck(parent context.Context, target *upstreamTarget, healthURL *url.URL) {
	timeout := target.health.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL.String(), nil)
	if err != nil {
		target.markFailure()
		return
	}
	resp, err := (&http.Client{Transport: target.transport}).Do(req)
	if err != nil {
		target.markFailure()
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	expected := target.health.expectedStatus
	if expected > 0 {
		if resp.StatusCode == expected {
			target.markSuccess()
		} else {
			target.markFailure()
		}
		return
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		target.markSuccess()
		return
	}
	target.markFailure()
}
