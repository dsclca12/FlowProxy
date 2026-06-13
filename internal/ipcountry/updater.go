package ipcountry

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"flowproxy/internal/settings"
)

var ipDenyBaseURL = "https://www.ipdeny.com"

type Updater struct {
	store     *settings.Store
	onUpdated func(settings.Settings)
	client    *http.Client

	triggerCh chan struct{}
	stopCh    chan struct{}
	doneCh    chan struct{}

	startMu sync.Mutex
	started bool
}

func NewUpdater(store *settings.Store, onUpdated func(settings.Settings)) *Updater {
	return &Updater{
		store:     store,
		onUpdated: onUpdated,
		client: &http.Client{
			Timeout: 45 * time.Second,
		},
		triggerCh: make(chan struct{}, 1),
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
}

func (u *Updater) Start() {
	u.startMu.Lock()
	if u.started {
		u.startMu.Unlock()
		return
	}
	u.started = true
	u.startMu.Unlock()

	go u.loop()
	u.Trigger()
}

func (u *Updater) Trigger() {
	select {
	case u.triggerCh <- struct{}{}:
	default:
	}
}

func (u *Updater) Close() {
	u.startMu.Lock()
	if !u.started {
		u.startMu.Unlock()
		return
	}
	u.started = false
	u.startMu.Unlock()

	close(u.stopCh)
	<-u.doneCh
}

func (u *Updater) loop() {
	defer close(u.doneCh)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-u.stopCh:
			return
		case <-ticker.C:
			u.syncNow(time.Now().UTC())
		case <-u.triggerCh:
			u.syncNow(time.Now().UTC())
		}
	}
}

func (u *Updater) syncNow(now time.Time) {
	if u.store == nil {
		return
	}
	current := u.store.Get()
	results := collectDueResults(now.UTC(), current, u.client)
	if len(results) == 0 {
		return
	}

	latest := u.store.Get()
	next, changed := applyResults(latest, results)
	if !changed {
		return
	}

	updated, err := u.store.Update(next)
	if err != nil {
		log.Printf("country ip auto update save failed: %v", err)
		return
	}
	if u.onUpdated != nil {
		u.onUpdated(updated)
	}
}

type autoUpdateResult struct {
	AttemptAt time.Time
	CIDRs     []string
	Error     string
}

func collectDueResults(now time.Time, st settings.Settings, client *http.Client) map[string]autoUpdateResult {
	out := map[string]autoUpdateResult{}
	for _, task := range st.IPCountryAutoUpdates {
		if !task.Enabled {
			continue
		}
		interval, err := time.ParseDuration(strings.TrimSpace(task.Interval))
		if err != nil || interval <= 0 {
			continue
		}
		if !task.LastAttemptAt.IsZero() && now.Before(task.LastAttemptAt.Add(interval)) {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		cidrs, err := fetchCIDRsForTask(ctx, client, task)
		cancel()

		result := autoUpdateResult{AttemptAt: now}
		if err != nil {
			result.Error = err.Error()
		} else {
			result.CIDRs = cidrs
		}
		out[strings.TrimSpace(task.ID)] = result
	}
	return out
}

func fetchCIDRsForTask(ctx context.Context, client *http.Client, task settings.IPCountryAutoUpdate) ([]string, error) {
	source := strings.ToLower(strings.TrimSpace(task.Source))
	if source == "" {
		source = "ipdeny"
	}
	if source != "ipdeny" {
		return nil, fmt.Errorf("unsupported source: %s", source)
	}

	raw := []string{}
	for _, country := range task.Countries {
		code := strings.ToLower(strings.TrimSpace(country))
		if code == "" {
			continue
		}
		v4URL := fmt.Sprintf("%s/ipblocks/data/countries/%s.zone", strings.TrimRight(ipDenyBaseURL, "/"), code)
		v4, err := fetchCIDRFile(ctx, client, v4URL)
		if err != nil {
			return nil, fmt.Errorf("%s ipv4 fetch failed: %w", strings.ToUpper(code), err)
		}
		raw = append(raw, v4...)

		if task.IncludeIPv6 {
			v6URL := fmt.Sprintf("%s/ipv6/ipaddresses/aggregated/%s-aggregated.zone", strings.TrimRight(ipDenyBaseURL, "/"), code)
			v6, err := fetchCIDRFile(ctx, client, v6URL)
			if err != nil {
				return nil, fmt.Errorf("%s ipv6 fetch failed: %w", strings.ToUpper(code), err)
			}
			raw = append(raw, v6...)
		}
	}

	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
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
	sort.Strings(out)
	return out, nil
}

func fetchCIDRFile(ctx context.Context, client *http.Client, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return parseCIDRLines(resp.Body)
}

func parseCIDRLines(body io.Reader) ([]string, error) {
	out := []string{}
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		_, network, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		canonical := network.String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func applyResults(st settings.Settings, results map[string]autoUpdateResult) (settings.Settings, bool) {
	if len(results) == 0 {
		return st, false
	}
	changed := false
	for i, task := range st.IPCountryAutoUpdates {
		result, ok := results[strings.TrimSpace(task.ID)]
		if !ok {
			continue
		}
		next := task
		next.LastAttemptAt = result.AttemptAt.UTC()
		if strings.TrimSpace(result.Error) != "" {
			next.LastError = strings.TrimSpace(result.Error)
		} else {
			next.CIDRs = append([]string{}, result.CIDRs...)
			next.LastSyncAt = result.AttemptAt.UTC()
			next.LastError = ""
		}
		if !countryTaskRuntimeEqual(task, next) {
			st.IPCountryAutoUpdates[i] = next
			changed = true
		}
	}
	return st, changed
}

func countryTaskRuntimeEqual(a settings.IPCountryAutoUpdate, b settings.IPCountryAutoUpdate) bool {
	if !a.LastAttemptAt.Equal(b.LastAttemptAt) {
		return false
	}
	if !a.LastSyncAt.Equal(b.LastSyncAt) {
		return false
	}
	if a.LastError != b.LastError {
		return false
	}
	if len(a.CIDRs) != len(b.CIDRs) {
		return false
	}
	for i := range a.CIDRs {
		if a.CIDRs[i] != b.CIDRs[i] {
			return false
		}
	}
	return true
}
