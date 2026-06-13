package clustersync

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"flowproxy/internal/certmgr"
	"flowproxy/internal/node"
	"flowproxy/internal/settings"
	"flowproxy/internal/site"
)

type Config struct {
	BaseURL  string
	BaseURLs []string
	Username string
	Password string
	Timeout  time.Duration
}

type Client struct {
	baseURLs      []string
	username      string
	password      string
	httpClient    *http.Client
	mu            sync.Mutex
	loggedInByURL map[string]bool
	activeIndex   int
	failuresByURL map[string]int
	cooldownUntil map[string]time.Time
}

var errClusterSyncUnauthorized = errors.New("cluster sync unauthorized")

func New(cfg Config) (*Client, error) {
	baseURLs := normalizeBaseURLs(cfg.BaseURL, cfg.BaseURLs)
	if len(baseURLs) == 0 {
		return nil, fmt.Errorf("cluster sync base url is required")
	}
	if strings.TrimSpace(cfg.Username) == "" {
		return nil, fmt.Errorf("cluster sync username is required")
	}
	if strings.TrimSpace(cfg.Password) == "" {
		return nil, fmt.Errorf("cluster sync password is required")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		baseURLs: baseURLs,
		username: strings.TrimSpace(cfg.Username),
		password: cfg.Password,
		httpClient: &http.Client{
			Timeout: timeout,
			Jar:     jar,
		},
		loggedInByURL: map[string]bool{},
		failuresByURL: map[string]int{},
		cooldownUntil: map[string]time.Time{},
	}, nil
}

func normalizeBaseURLs(baseURL string, baseURLs []string) []string {
	items := make([]string, 0, 1+len(baseURLs))
	seen := map[string]struct{}{}
	all := append([]string{baseURL}, baseURLs...)
	for _, item := range all {
		value := strings.TrimRight(strings.TrimSpace(item), "/")
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		items = append(items, value)
	}
	return items
}

func (c *Client) login(baseURL string) error {
	payload := map[string]string{
		"username": c.username,
		"password": c.password,
	}
	return c.doJSONOnce(baseURL, http.MethodPost, "/auth/login", payload, nil)
}

func (c *Client) UpsertNode(item node.Node) error {
	return c.doJSON(http.MethodPost, "/api/nodes", item, nil)
}

func (c *Client) Heartbeat(nodeID string) error {
	path := fmt.Sprintf("/api/nodes/%s/heartbeat", strings.TrimSpace(nodeID))
	return c.doJSON(http.MethodPost, path, nil, nil)
}

func (c *Client) FetchSites() ([]site.Site, error) {
	var items []site.Site
	if err := c.doJSON(http.MethodGet, "/api/sites", nil, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func (c *Client) FetchNodes() ([]node.Node, error) {
	var items []node.RuntimeNode
	if err := c.doJSON(http.MethodGet, "/api/nodes", nil, &items); err != nil {
		return nil, err
	}
	out := make([]node.Node, 0, len(items))
	for _, item := range items {
		out = append(out, item.Node)
	}
	return out, nil
}

func (c *Client) FetchSettings() (settings.Settings, error) {
	var out settings.Settings
	if err := c.doJSON(http.MethodGet, "/api/settings", nil, &out); err != nil {
		return settings.Settings{}, err
	}
	return out, nil
}

func (c *Client) FetchCertificates() ([]certmgr.Certificate, error) {
	var out []certmgr.Certificate
	if err := c.doJSON(http.MethodGet, "/api/certificates", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) FetchCertificateBundle(id string) ([]byte, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("certificate id is required")
	}
	query := url.Values{}
	query.Set("asset", "bundle")
	query.Set("format", "zip")
	path := fmt.Sprintf("/api/certificates/%s/download?%s", url.PathEscape(id), query.Encode())
	return c.getBytes(path)
}

func (c *Client) doJSON(method string, path string, payload any, out any) error {
	return c.withFailover(func(baseURL string) error {
		if path != "/auth/login" {
			if err := c.ensureLogin(baseURL); err != nil {
				return err
			}
		}
		if err := c.doJSONOnce(baseURL, method, path, payload, out); err != nil {
			if !errors.Is(err, errClusterSyncUnauthorized) || path == "/auth/login" {
				return err
			}
			if err := c.forceLogin(baseURL); err != nil {
				return err
			}
			return c.doJSONOnce(baseURL, method, path, payload, out)
		}
		return nil
	})
}

func (c *Client) doJSONOnce(baseURL string, method string, path string, payload any, out any) error {
	var body *bytes.Reader
	if payload == nil {
		body = bytes.NewReader(nil)
	} else {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, baseURL+path, body)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return errClusterSyncUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if strings.TrimSpace(apiErr.Error) != "" {
			return fmt.Errorf("cluster sync api error: %s", apiErr.Error)
		}
		return fmt.Errorf("cluster sync request failed: %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) ensureLogin(baseURL string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loggedInByURL[baseURL] {
		return nil
	}
	if err := c.login(baseURL); err != nil {
		return err
	}
	c.loggedInByURL[baseURL] = true
	return nil
}

func (c *Client) forceLogin(baseURL string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.login(baseURL); err != nil {
		return err
	}
	c.loggedInByURL[baseURL] = true
	return nil
}

func (c *Client) getBytes(path string) ([]byte, error) {
	var data []byte
	err := c.withFailover(func(baseURL string) error {
		if err := c.ensureLogin(baseURL); err != nil {
			return err
		}
		got, err := c.getBytesOnce(baseURL, path)
		if err != nil {
			if !errors.Is(err, errClusterSyncUnauthorized) {
				return err
			}
			if err := c.forceLogin(baseURL); err != nil {
				return err
			}
			got, err = c.getBytesOnce(baseURL, path)
			if err != nil {
				return err
			}
		}
		data = got
		return nil
	})
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (c *Client) getBytesOnce(baseURL string, path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errClusterSyncUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if strings.TrimSpace(apiErr.Error) != "" {
			return nil, fmt.Errorf("cluster sync api error: %s", apiErr.Error)
		}
		return nil, fmt.Errorf("cluster sync request failed: %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func (c *Client) withFailover(call func(baseURL string) error) error {
	baseURLs := c.snapshotBaseURLs()
	start := c.currentActiveIndex(len(baseURLs))
	ordered := c.prioritizeEligibleEndpoints(baseURLs, start, time.Now().UTC())
	var lastErr error
	for i := 0; i < len(ordered); i++ {
		endpoint := ordered[i]
		idx := indexOf(baseURLs, endpoint)
		if idx < 0 {
			continue
		}
		baseURL := baseURLs[idx]
		if err := call(baseURL); err != nil {
			lastErr = err
			if !shouldFailover(err) || i == len(baseURLs)-1 {
				return err
			}
			c.markFailureAndSwitch(baseURL, ordered[(i+1)%len(ordered)], err, time.Now().UTC())
			continue
		}
		c.markSuccess(baseURL)
		c.setActiveIndex(idx)
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("cluster sync request failed")
	}
	return lastErr
}

func shouldFailover(err error) bool {
	if errors.Is(err, errClusterSyncUnauthorized) {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if !strings.HasPrefix(msg, "cluster sync request failed:") {
		return true
	}
	return strings.HasPrefix(msg, "cluster sync request failed: 5")
}

func (c *Client) snapshotBaseURLs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.baseURLs...)
}

func (c *Client) currentActiveIndex(size int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if size <= 0 {
		return 0
	}
	if c.activeIndex < 0 || c.activeIndex >= size {
		c.activeIndex = 0
	}
	return c.activeIndex
}

func (c *Client) setActiveIndex(index int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if index < 0 || index >= len(c.baseURLs) {
		return
	}
	c.activeIndex = index
}

func (c *Client) markSwitch(from string, to string, reason error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.TrimSpace(from) != "" {
		delete(c.loggedInByURL, from)
	}
	log.Printf("cluster sync endpoint failover: %s -> %s (%v)", from, to, reason)
}

func (c *Client) markFailureAndSwitch(from string, to string, reason error, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if strings.TrimSpace(from) != "" {
		c.failuresByURL[from]++
		delete(c.loggedInByURL, from)
		fails := c.failuresByURL[from]
		cooldown := failoverCooldown(fails)
		c.cooldownUntil[from] = now.Add(cooldown)
	}
	log.Printf("cluster sync endpoint failover: %s -> %s (%v)", from, to, reason)
}

func (c *Client) markSuccess(baseURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.TrimSpace(baseURL) == "" {
		return
	}
	c.failuresByURL[baseURL] = 0
	delete(c.cooldownUntil, baseURL)
}

func (c *Client) prioritizeEligibleEndpoints(baseURLs []string, start int, now time.Time) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	eligible := make([]string, 0, len(baseURLs))
	held := make([]string, 0, len(baseURLs))
	for i := 0; i < len(baseURLs); i++ {
		idx := (start + i) % len(baseURLs)
		item := baseURLs[idx]
		until := c.cooldownUntil[item]
		if until.IsZero() || now.After(until) || now.Equal(until) {
			eligible = append(eligible, item)
			continue
		}
		held = append(held, item)
	}
	if len(eligible) > 0 {
		return append(eligible, held...)
	}
	return append([]string{}, baseURLs...)
}

func failoverCooldown(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	if failures > 6 {
		failures = 6
	}
	base := 2 * time.Second
	d := base
	for i := 1; i < failures; i++ {
		d *= 2
	}
	max := 60 * time.Second
	if d > max {
		return max
	}
	return d
}

func indexOf(items []string, target string) int {
	for i := range items {
		if items[i] == target {
			return i
		}
	}
	return -1
}

func (c *Client) ActiveEndpoint() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.baseURLs) == 0 {
		return ""
	}
	if c.activeIndex < 0 || c.activeIndex >= len(c.baseURLs) {
		c.activeIndex = 0
	}
	return c.baseURLs[c.activeIndex]
}
