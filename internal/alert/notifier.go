package alert

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Options struct {
	WebhookURL         string
	Consecutive5xx     int
	LatencyThresholdMs int64
	Cooldown           time.Duration
}

type Event struct {
	Timestamp  time.Time `json:"timestamp"`
	SiteID     string    `json:"siteId,omitempty"`
	Domain     string    `json:"domain,omitempty"`
	ClientIP   string    `json:"clientIp,omitempty"`
	Method     string    `json:"method,omitempty"`
	Path       string    `json:"path,omitempty"`
	StatusCode int       `json:"statusCode"`
	DurationMs int64     `json:"durationMs"`
	Upstream   string    `json:"upstream,omitempty"`
	Error      string    `json:"error,omitempty"`
}

type Notifier struct {
	webhookURL     string
	consecutive5xx int
	latencyMs      int64
	cooldown       time.Duration
	client         *http.Client
	queue          chan Event
	closeOnce      sync.Once
	closed         chan struct{}
}

type siteState struct {
	consecutive5xx   int
	last5xxAlert     time.Time
	lastLatencyAlert time.Time
}

func New(opts Options) *Notifier {
	webhook := strings.TrimSpace(opts.WebhookURL)
	if webhook == "" {
		return nil
	}
	threshold := opts.Consecutive5xx
	if threshold <= 0 {
		threshold = 10
	}
	cooldown := opts.Cooldown
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}
	n := &Notifier{
		webhookURL:     webhook,
		consecutive5xx: threshold,
		latencyMs:      opts.LatencyThresholdMs,
		cooldown:       cooldown,
		client: &http.Client{
			Timeout: 8 * time.Second,
		},
		queue:  make(chan Event, 1024),
		closed: make(chan struct{}),
	}
	go n.run()
	return n
}

func (n *Notifier) Close() {
	if n == nil {
		return
	}
	n.closeOnce.Do(func() {
		close(n.closed)
	})
}

func (n *Notifier) Record(event Event) {
	if n == nil {
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	select {
	case n.queue <- event:
	default:
		// drop when queue is full to avoid blocking request path
	}
}

func (n *Notifier) Emit(kind string, payload map[string]any) {
	if n == nil {
		return
	}
	kind = strings.TrimSpace(kind)
	if kind == "" {
		kind = "custom"
	}
	if payload == nil {
		payload = map[string]any{}
	}
	n.send(kind, payload)
}

func (n *Notifier) run() {
	states := map[string]siteState{}
	for {
		select {
		case <-n.closed:
			return
		case event := <-n.queue:
			key := strings.TrimSpace(event.SiteID)
			if key == "" {
				key = strings.TrimSpace(event.Domain)
			}
			if key == "" {
				key = "_global"
			}
			state := states[key]
			now := time.Now().UTC()

			if event.StatusCode >= 500 {
				state.consecutive5xx++
			} else {
				state.consecutive5xx = 0
			}

			if state.consecutive5xx >= n.consecutive5xx && now.Sub(state.last5xxAlert) >= n.cooldown {
				n.send("consecutive_5xx", map[string]any{
					"message":          "consecutive upstream/server failures exceeded threshold",
					"threshold":        n.consecutive5xx,
					"consecutiveCount": state.consecutive5xx,
					"event":            event,
				})
				state.last5xxAlert = now
			}

			if n.latencyMs > 0 && event.DurationMs >= n.latencyMs && now.Sub(state.lastLatencyAlert) >= n.cooldown {
				n.send("high_latency", map[string]any{
					"message":     "request latency exceeded threshold",
					"thresholdMs": n.latencyMs,
					"observedMs":  event.DurationMs,
					"statusCode":  event.StatusCode,
					"event":       event,
				})
				state.lastLatencyAlert = now
			}

			states[key] = state
		}
	}
}

func (n *Notifier) send(kind string, payload map[string]any) {
	body := map[string]any{
		"kind":      kind,
		"timestamp": time.Now().UTC(),
		"payload":   payload,
	}
	data, err := json.Marshal(body)
	if err != nil {
		log.Printf("alert marshal failed: %v", err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, n.webhookURL, bytes.NewReader(data))
	if err != nil {
		log.Printf("alert request failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("alert webhook post failed: %v", err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("alert webhook status: %d", resp.StatusCode)
	}
}
