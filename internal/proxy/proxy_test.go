package proxy

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"golang.org/x/crypto/bcrypt"

	"flowproxy/internal/site"
)

func TestRouterPathRoutingAndRewrite(t *testing.T) {
	var defaultPath string
	defaultUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defaultPath = req.URL.Path
		_, _ = w.Write([]byte("default"))
	}))
	defer defaultUpstream.Close()

	var apiPath string
	apiUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		apiPath = req.URL.Path
		_, _ = w.Write([]byte("api"))
	}))
	defer apiUpstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-1",
			Domain:   "example.com",
			Enabled:  true,
			Upstream: defaultUpstream.URL,
			Routes: []site.RouteRule{
				{
					Path:               "/api",
					Match:              site.MatchPrefix,
					Upstream:           apiUpstream.URL,
					RewritePattern:     "^/api",
					RewriteReplacement: "",
					Priority:           100,
				},
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	req1, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req1.Host = "example.com"
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("default request: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	if string(body1) != "default" {
		t.Fatalf("expected default upstream body, got %q", string(body1))
	}
	if defaultPath != "/" {
		t.Fatalf("expected default upstream path '/', got %q", defaultPath)
	}

	req2, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/api/v1/users", nil)
	req2.Host = "example.com"
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("api request: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if string(body2) != "api" {
		t.Fatalf("expected api upstream body, got %q", string(body2))
	}
	if apiPath != "/v1/users" {
		t.Fatalf("expected rewritten api path '/v1/users', got %q", apiPath)
	}
}

func TestRouterWildcardAndRateLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-2",
			Domain:   "*.demo.local",
			Enabled:  true,
			Upstream: upstream.URL,
			RateLimit: site.RateLimitConfig{
				Enabled:           true,
				RequestsPerMinute: 60,
				Burst:             1,
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	req1, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req1.Host = "api.demo.local"
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("wildcard request failed: %v", err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected first request to pass, got %d", resp1.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req2.Host = "api.demo.local"
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected second request to be rate limited, got %d", resp2.StatusCode)
	}
}

func TestRouterAutoBlockAndExpire(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-autoblock",
			Domain:   "ab.demo.local",
			Enabled:  true,
			Upstream: upstream.URL,
			RateLimit: site.RateLimitConfig{
				Enabled:           true,
				RequestsPerMinute: 60,
				Burst:             1,
				AutoBlock: site.AutoBlockConfig{
					Enabled:                true,
					ViolationThreshold:     1,
					ViolationWindowSeconds: 1,
					BlockSeconds:           1,
				},
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	doReq := func() int {
		req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
		req.Host = "ab.demo.local"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if code := doReq(); code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d", code)
	}
	if code := doReq(); code != http.StatusForbidden {
		t.Fatalf("expected second request 403 (auto blocked), got %d", code)
	}
	if code := doReq(); code != http.StatusForbidden {
		t.Fatalf("expected blocked request 403, got %d", code)
	}

	time.Sleep(1200 * time.Millisecond)

	if code := doReq(); code != http.StatusOK {
		t.Fatalf("expected request after block expiry 200, got %d", code)
	}
}

func TestRouterBasicAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("authorized"))
	}))
	defer upstream.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-3",
			Domain:   "secure.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
			BasicAuth: site.BasicAuthConfig{
				Enabled:      true,
				Username:     "admin",
				PasswordHash: string(hash),
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	req1, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req1.Host = "secure.example.com"
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("request without auth failed: %v", err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", resp1.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req2.Host = "secure.example.com"
	req2.SetBasicAuth("admin", "secret")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request with auth failed: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with auth, got %d", resp2.StatusCode)
	}
	if !strings.Contains(string(body), "authorized") {
		t.Fatalf("unexpected upstream body: %q", string(body))
	}
}

func TestDeniedByPolicyRespectsSourcePriority(t *testing.T) {
	base := site.Site{
		ID:      "s1",
		Domain:  "example.com",
		Enabled: true,
		IPAccessPolicy: site.IPAccessPolicy{
			Sources: []site.IPAccessSourceRules{
				{
					Source:     "country",
					DenyCIDRs:  []string{"203.0.113.0/24"},
					AllowCIDRs: []string{},
				},
				{
					Source:     "custom",
					AllowCIDRs: []string{"203.0.113.88"},
					DenyCIDRs:  []string{},
				},
			},
		},
	}

	base.IPAccessPolicy.SourceOrder = []string{"country", "custom"}
	p1, err := compileIPAccessPolicy(base)
	if err != nil {
		t.Fatalf("compile policy failed: %v", err)
	}
	if !deniedByPolicy(p1, "203.0.113.88", 0) {
		t.Fatalf("expected denied when country source has higher priority")
	}

	base.IPAccessPolicy.SourceOrder = []string{"custom", "country"}
	p2, err := compileIPAccessPolicy(base)
	if err != nil {
		t.Fatalf("compile policy failed: %v", err)
	}
	if deniedByPolicy(p2, "203.0.113.88", 0) {
		t.Fatalf("expected allowed when custom source has higher priority")
	}
}

func TestDeniedByPolicyKeepsAllowlistFallback(t *testing.T) {
	item := site.Site{
		ID:      "s1",
		Domain:  "example.com",
		Enabled: true,
		IPAccessPolicy: site.IPAccessPolicy{
			SourceOrder: []string{"custom"},
			Sources: []site.IPAccessSourceRules{
				{
					Source:     "custom",
					AllowCIDRs: []string{"10.0.0.1"},
				},
			},
		},
	}
	policy, err := compileIPAccessPolicy(item)
	if err != nil {
		t.Fatalf("compile policy failed: %v", err)
	}
	if deniedByPolicy(policy, "10.0.0.1", 0) {
		t.Fatalf("expected allow for listed ip")
	}
	if !deniedByPolicy(policy, "10.0.0.2", 0) {
		t.Fatalf("expected deny for non-allowlisted ip")
	}
}

func TestDeniedByPolicySupportsAllowFirstConflictPolicy(t *testing.T) {
	base := site.Site{
		ID:      "s1",
		Domain:  "example.com",
		Enabled: true,
		IPAccessPolicy: site.IPAccessPolicy{
			SourceOrder: []string{"custom:office"},
			Sources: []site.IPAccessSourceRules{
				{
					Source:         "custom:office",
					ConflictPolicy: "allow_first",
					AllowCIDRs:     []string{"10.0.0.0/8"},
					DenyCIDRs:      []string{"10.0.0.1"},
				},
			},
		},
	}

	allowFirstPolicy, err := compileIPAccessPolicy(base)
	if err != nil {
		t.Fatalf("compile policy failed: %v", err)
	}
	if deniedByPolicy(allowFirstPolicy, "10.0.0.1", 0) {
		t.Fatalf("expected allow when conflictPolicy=allow_first")
	}

	base.IPAccessPolicy.Sources[0].ConflictPolicy = "deny_first"
	denyFirstPolicy, err := compileIPAccessPolicy(base)
	if err != nil {
		t.Fatalf("compile policy failed: %v", err)
	}
	if !deniedByPolicy(denyFirstPolicy, "10.0.0.1", 0) {
		t.Fatalf("expected deny when conflictPolicy=deny_first")
	}
}

func TestDeniedByPolicySupportsASNAndReputation(t *testing.T) {
	item := site.Site{
		ID:      "s1",
		Domain:  "example.com",
		Enabled: true,
		IPAccessPolicy: site.IPAccessPolicy{
			SourceOrder: []string{"custom"},
			Sources: []site.IPAccessSourceRules{
				{
					Source:              "custom",
					AllowASNs:           []string{"AS13335"},
					DenyASNs:            []string{"15169"},
					DenyReputationCIDRs: []string{"198.51.100.0/24"},
				},
			},
		},
	}
	policy, err := compileIPAccessPolicy(item)
	if err != nil {
		t.Fatalf("compile policy failed: %v", err)
	}
	if deniedByPolicy(policy, "203.0.113.1", 13335) {
		t.Fatalf("expected allow for allowlisted asn")
	}
	if !deniedByPolicy(policy, "203.0.113.1", 15169) {
		t.Fatalf("expected deny for denylisted asn")
	}
	if !deniedByPolicy(policy, "198.51.100.7", 0) {
		t.Fatalf("expected deny for reputation ip")
	}
}

func TestClientASNFromRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	req.Header.Set("CF-ASN", "AS13335")
	if got := clientASNFromRequest(req); got != 13335 {
		t.Fatalf("unexpected asn: %d", got)
	}
	req2 := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	req2.Header.Set("X-Client-ASN", "15169, 13335")
	if got := clientASNFromRequest(req2); got != 15169 {
		t.Fatalf("unexpected asn from list: %d", got)
	}
}

func TestRouterRoutesByLocalListenPort(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("port-bound"))
	}))
	defer upstream.Close()

	rt := NewRouter()
	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	parsed, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	_, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatalf("failed to parse proxy port from %s: %v", parsed.Host, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("invalid proxy port: %v", err)
	}

	if err := rt.Load([]site.Site{
		{
			ID:         "site-port-only",
			ListenPort: port,
			Enabled:    true,
			Upstream:   upstream.URL,
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/health", nil)
	req.Host = "127.0.0.1:" + strconv.Itoa(port)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "port-bound" {
		t.Fatalf("unexpected upstream body: %q", string(body))
	}
}

func TestRouterAllowedMethods(t *testing.T) {
	var called atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-method",
			Domain:   "method.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
			TrafficControl: site.TrafficControlConfig{
				AllowedMethods: []string{"GET"},
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	req, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/submit", nil)
	req.Host = "method.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != "GET" {
		t.Fatalf("expected Allow header GET, got %q", got)
	}
	if called.Load() != 0 {
		t.Fatalf("expected upstream not called")
	}
}

func TestRouterConcurrencyLimit(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-concurrency",
			Domain:   "limit.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
			TrafficControl: site.TrafficControlConfig{
				MaxConcurrentRequests: 1,
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	firstDone := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/first", nil)
		req.Host = "limit.example.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			firstDone <- 0
			return
		}
		_ = resp.Body.Close()
		firstDone <- resp.StatusCode
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatalf("first request did not reach upstream in time")
	}

	req2, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/second", nil)
	req2.Host = "limit.example.com"
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected second request 429, got %d", resp2.StatusCode)
	}

	close(release)
	select {
	case code := <-firstDone:
		if code != http.StatusOK {
			t.Fatalf("expected first request 200, got %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("first request did not complete in time")
	}
}

func TestRouterBlocksUserAgentPattern(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-ua",
			Domain:   "ua.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
			Security: site.SecurityConfig{
				BlockUserAgentPatterns: []string{`(?i)curl`},
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	blockedReq, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	blockedReq.Host = "ua.example.com"
	blockedReq.Header.Set("User-Agent", "curl/8.9.0")
	blockedResp, err := http.DefaultClient.Do(blockedReq)
	if err != nil {
		t.Fatalf("blocked request failed: %v", err)
	}
	_ = blockedResp.Body.Close()
	if blockedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected blocked request 403, got %d", blockedResp.StatusCode)
	}

	passReq, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	passReq.Host = "ua.example.com"
	passReq.Header.Set("User-Agent", "Mozilla/5.0")
	passResp, err := http.DefaultClient.Do(passReq)
	if err != nil {
		t.Fatalf("pass request failed: %v", err)
	}
	_ = passResp.Body.Close()
	if passResp.StatusCode != http.StatusOK {
		t.Fatalf("expected pass request 200, got %d", passResp.StatusCode)
	}
}

func TestRouterCanaryByHeader(t *testing.T) {
	stable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("stable"))
	}))
	defer stable.Close()
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("canary"))
	}))
	defer canary.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-canary",
			Domain:   "canary.example.com",
			Enabled:  true,
			Upstream: stable.URL,
			Canary: site.CanaryConfig{
				Enabled:     true,
				Header:      "X-Canary",
				HeaderValue: "1",
				Upstream:    canary.URL,
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	stableReq, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	stableReq.Host = "canary.example.com"
	stableResp, err := http.DefaultClient.Do(stableReq)
	if err != nil {
		t.Fatalf("stable request failed: %v", err)
	}
	stableBody, _ := io.ReadAll(stableResp.Body)
	_ = stableResp.Body.Close()
	if string(stableBody) != "stable" {
		t.Fatalf("expected stable response, got %q", string(stableBody))
	}

	canaryReq, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	canaryReq.Host = "canary.example.com"
	canaryReq.Header.Set("X-Canary", "1")
	canaryResp, err := http.DefaultClient.Do(canaryReq)
	if err != nil {
		t.Fatalf("canary request failed: %v", err)
	}
	canaryBody, _ := io.ReadAll(canaryResp.Body)
	_ = canaryResp.Body.Close()
	if string(canaryBody) != "canary" {
		t.Fatalf("expected canary response, got %q", string(canaryBody))
	}
}

func TestRouterRetryOnConfiguredStatus(t *testing.T) {
	var unstableCalled atomic.Int64
	unstable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		unstableCalled.Add(1)
		http.Error(w, "try next", http.StatusServiceUnavailable)
	}))
	defer unstable.Close()
	stable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer stable.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:      "site-retry",
			Domain:  "retry.example.com",
			Enabled: true,
			Upstreams: []site.Upstream{
				{URL: unstable.URL, Weight: 1},
				{URL: stable.URL, Weight: 1},
			},
			Resilience: site.ResilienceConfig{
				Retry: site.RetryConfig{
					Enabled:         true,
					Attempts:        2,
					RetryOnStatuses: []int{http.StatusServiceUnavailable},
				},
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req.Host = "retry.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after retry, got %d", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Fatalf("expected stable response body, got %q", string(body))
	}
	if unstableCalled.Load() == 0 {
		t.Fatalf("expected unstable upstream to be called at least once")
	}
}

func TestRouterUpstreamTLSInsecureSkipVerify(t *testing.T) {
	secureUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("secure-ok"))
	}))
	defer secureUpstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-upstream-tls",
			Domain:   "secure-up.example.com",
			Enabled:  true,
			Upstream: secureUpstream.URL,
			UpstreamTLS: site.UpstreamTLSConfig{
				InsecureSkipVerify: true,
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req.Host = "secure-up.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "secure-ok" {
		t.Fatalf("unexpected upstream response: %q", string(body))
	}
}

func TestRouterAddsDefaultSecurityHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-headers",
			Domain:   "secure-headers.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
			Security: site.SecurityConfig{
				EnableSecurityHeaders: true,
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req.Host = "secure-headers.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()

	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing X-Content-Type-Options")
	}
	if resp.Header.Get("X-Frame-Options") == "" {
		t.Fatalf("missing X-Frame-Options")
	}
	if resp.Header.Get("Referrer-Policy") == "" {
		t.Fatalf("missing Referrer-Policy")
	}
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Fatalf("did not expect HSTS on plain HTTP request")
	}
}

func TestRouterAutoRequestHeadersSanitizeUntrustedForwarded(t *testing.T) {
	var xRealIP string
	var xForwardedFor string
	var xForwardedPort string
	var xRequestID string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		xRealIP = req.Header.Get("X-Real-IP")
		xForwardedFor = req.Header.Get("X-Forwarded-For")
		xForwardedPort = req.Header.Get("X-Forwarded-Port")
		xRequestID = req.Header.Get("X-Request-ID")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:                 "site-auto-req",
			Domain:             "auto-req.example.com",
			Enabled:            true,
			Upstream:           upstream.URL,
			AutoRequestHeaders: true,
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req.Host = "auto-req.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.88")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	if xRealIP == "" {
		t.Fatalf("expected X-Real-IP to be auto-configured")
	}
	if xForwardedPort == "" {
		t.Fatalf("expected X-Forwarded-Port to be auto-configured")
	}
	if xRequestID == "" {
		t.Fatalf("expected X-Request-ID to be forwarded")
	}
	if strings.Contains(xForwardedFor, "203.0.113.88") {
		t.Fatalf("expected spoofed X-Forwarded-For to be sanitized, got %q", xForwardedFor)
	}
}

func TestRouterAutoResponseHeadersAddsRequestID(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:                  "site-auto-resp",
			Domain:              "auto-resp.example.com",
			Enabled:             true,
			Upstream:            upstream.URL,
			AutoResponseHeaders: true,
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req.Host = "auto-resp.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Request-ID") == "" {
		t.Fatalf("expected X-Request-ID response header")
	}
	if resp.Header.Get("X-Proxy-By") != "FlowProxy" {
		t.Fatalf("expected X-Proxy-By header")
	}
}

func TestRouterRouteConditions(t *testing.T) {
	defaultUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("default"))
	}))
	defer defaultUpstream.Close()
	conditionalUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("conditional"))
	}))
	defer conditionalUpstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-route-conditions",
			Domain:   "cond.example.com",
			Enabled:  true,
			Upstream: defaultUpstream.URL,
			Routes: []site.RouteRule{
				{
					Path:        "/api",
					Match:       site.MatchPrefix,
					Methods:     []string{"GET"},
					Header:      "X-Api-Version",
					HeaderValue: "v2",
					Cookie:      "beta_user",
					CookieValue: "1",
					Query:       "stage",
					QueryValue:  "canary",
					Upstream:    conditionalUpstream.URL,
					Priority:    100,
				},
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/api/orders?stage=canary", nil)
	req.Host = "cond.example.com"
	req.Header.Set("X-Api-Version", "v2")
	req.AddCookie(&http.Cookie{Name: "beta_user", Value: "1"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "conditional" {
		t.Fatalf("expected conditional route upstream, got %q", string(body))
	}

	fallbackReq, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/api/orders?stage=prod", nil)
	fallbackReq.Host = "cond.example.com"
	fallbackReq.Header.Set("X-Api-Version", "v2")
	fallbackReq.AddCookie(&http.Cookie{Name: "beta_user", Value: "1"})
	fallbackResp, err := http.DefaultClient.Do(fallbackReq)
	if err != nil {
		t.Fatalf("fallback request failed: %v", err)
	}
	fallbackBody, _ := io.ReadAll(fallbackResp.Body)
	_ = fallbackResp.Body.Close()
	if string(fallbackBody) != "default" {
		t.Fatalf("expected fallback default upstream, got %q", string(fallbackBody))
	}
}

func TestRouterRequestTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(120 * time.Millisecond)
		_, _ = w.Write([]byte("slow"))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-timeout",
			Domain:   "timeout.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
			Timeouts: site.TimeoutConfig{
				RequestMillis: 50,
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/slow", nil)
	req.Host = "timeout.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout && resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected timeout-like status, got %d", resp.StatusCode)
	}
}

func TestRouterCacheKeyIgnoreQueryParams(t *testing.T) {
	var called atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := called.Add(1)
		_, _ = w.Write([]byte(fmt.Sprintf("payload-%d", n)))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-cache-key",
			Domain:   "cache-key.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
			Cache: site.CacheConfig{
				Enabled:              true,
				Proactive:            true,
				TTLSeconds:           30,
				MaxEntries:           32,
				MaxBodyBytes:         4096,
				KeyIgnoreQueryParams: []string{"token", "ts"},
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	doReq := func(uri string) string {
		req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+uri, nil)
		req.Host = "cache-key.example.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	first := doReq("/data?a=1&token=aaa&ts=1")
	second := doReq("/data?token=bbb&a=1&ts=999")
	if first != second {
		t.Fatalf("expected ignored-query cache hit, got %q vs %q", first, second)
	}
	third := doReq("/data?a=2&token=ccc")
	if third == first {
		t.Fatalf("expected different cache key when non-ignored query changes")
	}
}

func TestRouterPurgeSiteCache(t *testing.T) {
	var called atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := called.Add(1)
		_, _ = w.Write([]byte(fmt.Sprintf("cache-%d", n)))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-purge-cache",
			Domain:   "purge.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
			Cache: site.CacheConfig{
				Enabled:      true,
				Proactive:    true,
				TTLSeconds:   30,
				MaxEntries:   64,
				MaxBodyBytes: 4096,
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	request := func() string {
		req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/x", nil)
		req.Host = "purge.example.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	before := request()
	cached := request()
	if before != cached {
		t.Fatalf("expected cached response before purge")
	}
	purged, ok := rt.PurgeSiteCache("site-purge-cache")
	if !ok || purged <= 0 {
		t.Fatalf("expected purge to remove cached entries, ok=%v purged=%d", ok, purged)
	}
	after := request()
	if after == before {
		t.Fatalf("expected cache miss after purge")
	}
}

func TestRetryPolicyBackoffExponential(t *testing.T) {
	p := resolveRetryPolicy(site.RetryConfig{
		Enabled:          true,
		Attempts:         4,
		RetryOnStatuses:  []int{503},
		BackoffStrategy:  site.RetryBackoffExponential,
		BackoffMillis:    100,
		MaxBackoffMillis: 250,
	})
	if got := p.backoffDelay(0); got != 100*time.Millisecond {
		t.Fatalf("expected first backoff 100ms, got %v", got)
	}
	if got := p.backoffDelay(1); got != 200*time.Millisecond {
		t.Fatalf("expected second backoff 200ms, got %v", got)
	}
	if got := p.backoffDelay(2); got != 250*time.Millisecond {
		t.Fatalf("expected third backoff capped at 250ms, got %v", got)
	}
	if !p.shouldRetry(http.StatusServiceUnavailable) {
		t.Fatalf("expected status 503 to be retryable")
	}
	if p.shouldRetry(http.StatusInternalServerError) {
		t.Fatalf("did not expect status 500 to be retryable with explicit status list")
	}
}

func TestClientIPFromRequestTrustedProxy(t *testing.T) {
	trustedRules, err := parseIPRules([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("parse trusted rules failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "127.0.0.1:53210"
	req.Header.Set("X-Forwarded-For", "203.0.113.8, 127.0.0.1")

	ip := clientIPFromRequest(req, true, trustedRules)
	if ip != "203.0.113.8" {
		t.Fatalf("expected forwarded client ip, got %s", ip)
	}
}

func TestClientIPFromRequestUntrustedIgnoresForwarded(t *testing.T) {
	trustedRules, err := parseIPRules([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("parse trusted rules failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:40000"
	req.Header.Set("X-Forwarded-For", "203.0.113.8")

	ip := clientIPFromRequest(req, isForwardedHeadersTrusted(req, trustedRules), trustedRules)
	if ip != "198.51.100.10" {
		t.Fatalf("expected remote addr ip, got %s", ip)
	}
}

func TestSchemeFromRequestTrustedProxy(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	if got := schemeFromRequest(req, true); got != "https" {
		t.Fatalf("expected https, got %s", got)
	}
	if got := schemeFromRequest(req, false); got != "http" {
		t.Fatalf("expected untrusted forwarded proto to be ignored, got %s", got)
	}
}

func TestRouterResponseCache(t *testing.T) {
	var called atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := called.Add(1)
		_, _ = w.Write([]byte(fmt.Sprintf("ok-%d", n)))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-cache",
			Domain:   "cache.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
			Cache: site.CacheConfig{
				Enabled:      true,
				Proactive:    true,
				TTLSeconds:   30,
				MaxEntries:   100,
				MaxBodyBytes: 4096,
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	doReq := func() string {
		req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/v1/data?id=1", nil)
		req.Host = "cache.example.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		return string(body)
	}

	first := doReq()
	second := doReq()
	if first != second {
		t.Fatalf("expected cached response, got %q and %q", first, second)
	}
	if called.Load() != 1 {
		t.Fatalf("expected upstream called once, got %d", called.Load())
	}
}

func TestRouterPassiveCacheRequiresCacheHeaders(t *testing.T) {
	var called atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := called.Add(1)
		if n%2 == 1 {
			w.Header().Set("Cache-Control", "public, max-age=60")
		}
		_, _ = w.Write([]byte(fmt.Sprintf("ok-%d", n)))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-cache-passive",
			Domain:   "cache-passive.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
			Cache: site.CacheConfig{
				Enabled:      true,
				Proactive:    false,
				TTLSeconds:   30,
				MaxEntries:   100,
				MaxBodyBytes: 4096,
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	// First request has cacheable headers, should be cached.
	req1, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/cached", nil)
	req1.Host = "cache-passive.example.com"
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()

	req2, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/cached", nil)
	req2.Host = "cache-passive.example.com"
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if string(body1) != string(body2) {
		t.Fatalf("expected passive cached response to match, got %q and %q", string(body1), string(body2))
	}

	// Different path with no cache-control should not be cached in passive mode.
	req3, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/nocache", nil)
	req3.Host = "cache-passive.example.com"
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("third request failed: %v", err)
	}
	body3, _ := io.ReadAll(resp3.Body)
	_ = resp3.Body.Close()

	req4, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/nocache", nil)
	req4.Host = "cache-passive.example.com"
	resp4, err := http.DefaultClient.Do(req4)
	if err != nil {
		t.Fatalf("fourth request failed: %v", err)
	}
	body4, _ := io.ReadAll(resp4.Body)
	_ = resp4.Body.Close()
	if string(body3) == string(body4) {
		t.Fatalf("expected passive mode without cache headers to skip caching")
	}
}

func TestRouterGzipCompression(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("hello-gzip"))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-gzip",
			Domain:   "gzip.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
			Gzip: site.GzipConfig{
				Enabled: true,
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}

	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req.Host = "gzip.example.com"
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := strings.ToLower(resp.Header.Get("Content-Encoding")); got != "gzip" {
		t.Fatalf("expected gzip content-encoding, got %q", got)
	}
	reader, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("new gzip reader failed: %v", err)
	}
	defer reader.Close()
	body, _ := io.ReadAll(reader)
	if string(body) != "hello-gzip" {
		t.Fatalf("unexpected gzipped body: %q", string(body))
	}
}

func TestRouterBrotliCompressionPreferred(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"hello-br"}`))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-br",
			Domain:   "br.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
			Gzip: site.GzipConfig{
				Enabled: true,
			},
			Brotli: site.BrotliConfig{
				Enabled: true,
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}

	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req.Host = "br.example.com"
	req.Header.Set("Accept-Encoding", "gzip;q=0.8, br;q=1")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if got := strings.ToLower(resp.Header.Get("Content-Encoding")); got != "br" {
		t.Fatalf("expected br content-encoding, got %q", got)
	}
	reader := brotli.NewReader(resp.Body)
	body, _ := io.ReadAll(reader)
	if string(body) != `{"message":"hello-br"}` {
		t.Fatalf("unexpected brotli body: %q", string(body))
	}
}

func TestRouterBrotliDisabledByClientFallsBackToGzip(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("hello-fallback"))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-br-fallback",
			Domain:   "br-fallback.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
			Gzip: site.GzipConfig{
				Enabled: true,
			},
			Brotli: site.BrotliConfig{
				Enabled: true,
			},
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}

	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req.Host = "br-fallback.example.com"
	req.Header.Set("Accept-Encoding", "br;q=0, gzip;q=1")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if got := strings.ToLower(resp.Header.Get("Content-Encoding")); got != "gzip" {
		t.Fatalf("expected gzip content-encoding, got %q", got)
	}
	reader, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("new gzip reader failed: %v", err)
	}
	defer reader.Close()
	body, _ := io.ReadAll(reader)
	if string(body) != "hello-fallback" {
		t.Fatalf("unexpected fallback body: %q", string(body))
	}
}

func TestRouterWebSocketUpgradeProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !isUpgradeRequest(req.Header) {
			http.Error(w, "upgrade required", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatalf("upstream does not support hijacker")
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			t.Fatalf("upstream hijack failed: %v", err)
		}
		defer conn.Close()

		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
		_, _ = rw.WriteString("Connection: Upgrade\r\n")
		_, _ = rw.WriteString("Upgrade: websocket\r\n")
		_, _ = rw.WriteString("\r\n")
		_ = rw.Flush()

		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = rw.WriteString("echo:" + line)
		_ = rw.Flush()
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-ws",
			Domain:   "ws.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	proxyServer := httptest.NewServer(rt)
	defer proxyServer.Close()

	parsed, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	conn, err := net.Dial("tcp", parsed.Host)
	if err != nil {
		t.Fatalf("dial proxy failed: %v", err)
	}
	defer conn.Close()

	_, _ = fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\n")
	_, _ = fmt.Fprintf(conn, "Host: ws.example.com\r\n")
	_, _ = fmt.Fprintf(conn, "Connection: Upgrade\r\n")
	_, _ = fmt.Fprintf(conn, "Upgrade: websocket\r\n")
	_, _ = fmt.Fprintf(conn, "\r\n")

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line failed: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101 response, got %q", statusLine)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read upgrade headers failed: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	_, _ = conn.Write([]byte("ping\n"))
	echoLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read tunneled data failed: %v", err)
	}
	if echoLine != "echo:ping\n" {
		t.Fatalf("unexpected tunneled payload: %q", echoLine)
	}
}

func TestRouterSingleUpstreamMarkedUnhealthyStillProxies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	rt := NewRouter()
	if err := rt.Load([]site.Site{
		{
			ID:       "site-single-unhealthy",
			Domain:   "single.example.com",
			Enabled:  true,
			Upstream: upstream.URL,
		},
	}); err != nil {
		t.Fatalf("load router: %v", err)
	}

	compiled := rt.lookupSite("single.example.com")
	if compiled == nil || compiled.defaultPool == nil || len(compiled.defaultPool.targets) != 1 {
		t.Fatalf("expected one compiled upstream target")
	}
	target := compiled.defaultPool.targets[0]
	for i := 0; i < passiveFailThreshold; i++ {
		target.markFailure()
	}

	server := httptest.NewServer(rt)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	req.Host = "single.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when single upstream is marked unhealthy, got %d body=%q", resp.StatusCode, string(body))
	}
	if string(body) != "ok" {
		t.Fatalf("expected upstream body, got %q", string(body))
	}
}
