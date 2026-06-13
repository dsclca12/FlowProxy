package proxy

import (
	"bufio"
	"compress/gzip"
	"container/list"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"golang.org/x/crypto/bcrypt"

	"flowproxy/internal/jwtauth"
	"flowproxy/internal/oauth"
	"flowproxy/internal/settings"
	"flowproxy/internal/site"
	"flowproxy/internal/waf"
)

const (
	maxRecentLogs             = 400
	passiveFailThreshold      = 3
	passiveRecoverWindow      = 30 * time.Second
	defaultHSTSValue          = "max-age=31536000; includeSubDomains"
	defaultAutoBlockThreshold = 5
	defaultAutoBlockWindow    = 60 * time.Second
	defaultAutoBlockDuration  = 10 * time.Minute
	defaultCacheTTL           = 30 * time.Second
	defaultCacheMaxEntries    = 512
	defaultCacheMaxBodyBytes  = 1 << 20 // 1MiB
)

type Router struct {
	mu sync.RWMutex

	exactHosts        map[string]*compiledSite
	wildcards         []wildcardHost
	portSites         map[int]*compiledSite
	siteByID          map[string]*compiledSite
	domains           []string
	trustedProxyRules []ipRule
	alertHook         func(AccessLogEntry)
	healthCancel      func()

	totalSites   int
	enabledSites int

	statsMu      sync.RWMutex
	totalReq     atomic.Uint64
	successReq   atomic.Uint64
	failedReq    atomic.Uint64
	totalLatency atomic.Uint64
	siteStats    map[string]*siteMetric
	logs         []AccessLogEntry
	logStore     *AccessLogStore

	logSubsMu sync.Mutex
	logSubs   map[string]chan AccessLogEntry
}

type StatsSnapshot struct {
	Timestamp        time.Time            `json:"timestamp"`
	TotalSites       int                  `json:"totalSites"`
	EnabledSites     int                  `json:"enabledSites"`
	TotalRequests    uint64               `json:"totalRequests"`
	SuccessRequests  uint64               `json:"successRequests"`
	FailedRequests   uint64               `json:"failedRequests"`
	AverageLatencyMs float64              `json:"averageLatencyMs"`
	SuccessRate      float64              `json:"successRate"`
	TopSites         []SiteMetricSnapshot `json:"topSites"`
}

type SiteMetricSnapshot struct {
	SiteID           string  `json:"siteId"`
	Domain           string  `json:"domain"`
	Requests         uint64  `json:"requests"`
	SuccessRequests  uint64  `json:"successRequests"`
	FailedRequests   uint64  `json:"failedRequests"`
	AverageLatencyMs float64 `json:"averageLatencyMs"`
}

type AccessLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	SiteID     string    `json:"siteId,omitempty"`
	Domain     string    `json:"domain,omitempty"`
	ClientIP   string    `json:"clientIp"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	StatusCode int       `json:"statusCode"`
	DurationMs int64     `json:"durationMs"`
	Upstream   string    `json:"upstream,omitempty"`
	UserAgent  string    `json:"userAgent,omitempty"`
	Error      string    `json:"error,omitempty"`
}

type compiledSite struct {
	cfg site.Site

	defaultPool *upstreamPool
	canary      *canaryRule
	routes      []compiledRoute
	cache       *responseCache
	compression compressionPolicy

	requestHeaders        []site.Header
	responseHeaders       []site.Header
	removeRequestHeaders  []string
	removeResponseHeaders []string
	autoRequestHeaders    bool
	autoResponseHeaders   bool
	cacheIgnoreQuerySet   map[string]struct{}
	requestTimeout        time.Duration

	ipPolicy            compiledIPAccessPolicy
	limiter             *rateLimiter
	allowedMethods      map[string]struct{}
	allowedMethodsOrder []string
	blockedUserAgents   []*regexp.Regexp
	maxConcurrent       int64
	activeRequests      atomic.Int64
	maxConcurrentPerIP  int64
	perIPRequests       map[string]*atomic.Int64
	perIPMu             sync.Mutex

	jwtValidator *jwtauth.Validator
	wafEngine    *waf.Engine

	oauthSessionManager *oauth.SessionManager
	oauthConfig         oauth.SiteConfig
	oauthProvider       oauth.Provider
}

type wildcardHost struct {
	suffix string
	site   *compiledSite
}

type compiledRoute struct {
	matchType          string
	path               string
	pathRegex          *regexp.Regexp
	methods            map[string]struct{}
	header             string
	headerValue        string
	cookie             string
	cookieValue        string
	query              string
	queryValue         string
	rewriteRegex       *regexp.Regexp
	rewriteReplacement string
	priority           int
	pool               *upstreamPool
}

type upstreamPool struct {
	name         string
	strategy     string
	targets      []*upstreamTarget
	weightedPlan []int
	rrCounter    atomic.Uint64
	retry        retryPolicy
}

type upstreamTarget struct {
	key            string
	url            *url.URL
	proxy          *httputil.ReverseProxy
	transport      http.RoundTripper
	weight         int
	active         atomic.Int64
	failures       atomic.Int64
	unhealthyUntil atomic.Int64
	health         activeHealthPolicy
	circuit        circuitBreakerPolicy
	cbFailures     atomic.Int64
	cbOpenUntil    atomic.Int64
}

type ipRule struct {
	ip  net.IP
	net *net.IPNet
}

type compiledIPAccessSource struct {
	source         string
	allowFirst     bool
	allow          []ipRule
	deny           []ipRule
	allowASNs      map[uint32]struct{}
	denyASNs       map[uint32]struct{}
	denyReputation []ipRule
}

type compiledIPAccessPolicy struct {
	sources  []compiledIPAccessSource
	anyAllow bool
}

type rateLimiter struct {
	mu         sync.Mutex
	byIP       map[string]*bucketState
	ratePerSec float64
	burst      float64
	autoBlock  autoBlockPolicy
}

type bucketState struct {
	tokens               float64
	last                 time.Time
	violationCount       int
	violationWindowStart time.Time
	blockedUntil         time.Time
}

type autoBlockPolicy struct {
	enabled            bool
	violationThreshold int
	violationWindow    time.Duration
	blockDuration      time.Duration
}

type rateLimitDecision struct {
	allowed    bool
	blocked    bool
	retryAfter time.Duration
}

type siteMetric struct {
	siteID       string
	domain       string
	requests     uint64
	success      uint64
	failed       uint64
	totalLatency uint64
}

type retryPolicy struct {
	enabled           bool
	attempts          int
	statuses          map[int]struct{}
	statusList        []int
	backoff           time.Duration
	maxBackoff        time.Duration
	jitterPercent     int
	backoffStrategy   string
	retryOn5xx        bool
	retryOnTimeout    bool
	retryOnConnection bool
}

type activeHealthPolicy struct {
	enabled        bool
	interval       time.Duration
	timeout        time.Duration
	path           string
	expectedStatus int
}

type circuitBreakerPolicy struct {
	enabled          bool
	failureThreshold int64
	openDuration     time.Duration
}

type canaryRule struct {
	pool        *upstreamPool
	header      string
	headerValue string
	cookie      string
	cookieValue string
	weight      int
}

type cachePolicy struct {
	enabled      bool
	ttl          time.Duration
	maxEntries   int
	maxBodyBytes int
	proactive    bool
}

type compressionPolicy struct {
	gzipEnabled   bool
	brotliEnabled bool
}

type compressionAlgorithm string

const (
	compressionNone   compressionAlgorithm = ""
	compressionGzip   compressionAlgorithm = "gzip"
	compressionBrotli compressionAlgorithm = "br"
)

type responseCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	lruList *list.List
	policy  cachePolicy
}

type cacheEntry struct {
	status    int
	header    http.Header
	body      []byte
	expiresAt time.Time
	lruElem   *list.Element
}

type lruKey struct {
	key string
}

func NewRouter() *Router {
	return &Router{
		exactHosts:        map[string]*compiledSite{},
		portSites:         map[int]*compiledSite{},
		siteByID:          map[string]*compiledSite{},
		siteStats:         map[string]*siteMetric{},
		trustedProxyRules: []ipRule{},
		logSubs:           map[string]chan AccessLogEntry{},
	}
}

func (r *Router) SetAccessLogStore(store *AccessLogStore) {
	r.statsMu.Lock()
	r.logStore = store
	r.statsMu.Unlock()
}

func (r *Router) SetTrustedProxyCIDRs(items []string) error {
	rules, err := parseIPRules(items)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.trustedProxyRules = rules
	r.mu.Unlock()
	return nil
}

func (r *Router) SetAlertHook(fn func(AccessLogEntry)) {
	r.mu.Lock()
	r.alertHook = fn
	r.mu.Unlock()
}

func (r *Router) Close() {
	r.mu.Lock()
	cancel := r.healthCancel
	r.healthCancel = nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// SubscribeLogs registers a channel to receive real-time access log entries.
// The caller must eventually call UnsubscribeLogs with the returned ID.
func (r *Router) SubscribeLogs(ch chan AccessLogEntry) string {
	id := newRequestID()
	r.logSubsMu.Lock()
	r.logSubs[id] = ch
	r.logSubsMu.Unlock()
	return id
}

// UnsubscribeLogs removes a previously registered log subscriber.
func (r *Router) UnsubscribeLogs(id string) {
	r.logSubsMu.Lock()
	delete(r.logSubs, id)
	r.logSubsMu.Unlock()
}

func (r *Router) broadcastLogEntry(entry AccessLogEntry) {
	r.logSubsMu.Lock()
	n := len(r.logSubs)
	if n == 0 {
		r.logSubsMu.Unlock()
		return
	}
	ids := make([]string, 0, n)
	chs := make([]chan AccessLogEntry, 0, n)
	for id, ch := range r.logSubs {
		ids = append(ids, id)
		chs = append(chs, ch)
	}
	r.logSubsMu.Unlock()
	for i, ch := range chs {
		select {
		case ch <- entry:
		default:
			// Drop if subscriber is too slow; close stale subscription
			r.logSubsMu.Lock()
			delete(r.logSubs, ids[i])
			close(ch)
			r.logSubsMu.Unlock()
		}
	}
}

func (r *Router) Load(sites []site.Site) error {
	exact := map[string]*compiledSite{}
	wildcards := make([]wildcardHost, 0)
	portSites := map[int]*compiledSite{}
	siteByID := map[string]*compiledSite{}
	domainSet := map[string]struct{}{}
	healthTargets := make([]*upstreamTarget, 0)

	totalSites := len(sites)
	enabledSites := 0

	for _, item := range sites {
		if !item.Enabled {
			continue
		}
		if IsL4Site(item) {
			// L4 port forwarding sites are handled by L4Proxy, not the HTTP router
			continue
		}
		enabledSites++
		compiled, err := compileSite(item)
		if err != nil {
			return fmt.Errorf("site %s compile failed: %w", item.ID, err)
		}
		siteByID[item.ID] = compiled
		healthTargets = append(healthTargets, compiled.healthTargets()...)
		if item.ListenPort > 0 {
			if _, exists := portSites[item.ListenPort]; exists {
				return fmt.Errorf("duplicate listen port in enabled sites: %d", item.ListenPort)
			}
			portSites[item.ListenPort] = compiled
		}

		for _, domain := range site.AllDomains(item) {
			if strings.HasPrefix(domain, "*.") {
				suffix := strings.TrimPrefix(domain, "*")
				wildcards = append(wildcards, wildcardHost{
					suffix: suffix,
					site:   compiled,
				})
				continue
			}
			if _, exists := exact[domain]; exists {
				return fmt.Errorf("duplicate domain in enabled sites: %s", domain)
			}
			exact[domain] = compiled
			domainSet[domain] = struct{}{}
		}
	}

	sort.Slice(wildcards, func(i, j int) bool {
		return len(wildcards[i].suffix) > len(wildcards[j].suffix)
	})

	domains := make([]string, 0, len(domainSet))
	for domain := range domainSet {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	r.mu.Lock()
	if r.healthCancel != nil {
		r.healthCancel()
		r.healthCancel = nil
	}
	r.exactHosts = exact
	r.wildcards = wildcards
	r.portSites = portSites
	r.siteByID = siteByID
	r.domains = domains
	r.totalSites = totalSites
	r.enabledSites = enabledSites
	r.mu.Unlock()
	r.startHealthChecks(healthTargets)

	return nil
}

func (r *Router) Domains() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.domains))
	copy(out, r.domains)
	return out
}

func (r *Router) CertificateIDForHost(host string) string {
	normalized := normalizeRequestHost(host)
	if normalized == "" {
		return ""
	}
	siteCfg := r.lookupSite(normalized)
	if siteCfg == nil {
		return ""
	}
	return strings.TrimSpace(siteCfg.cfg.CertificateID)
}

func (r *Router) PurgeSiteCache(siteID string) (int, bool) {
	siteID = strings.TrimSpace(siteID)
	if siteID == "" {
		return 0, false
	}
	r.mu.RLock()
	siteCfg, ok := r.siteByID[siteID]
	r.mu.RUnlock()
	if !ok || siteCfg == nil {
		return 0, false
	}
	return siteCfg.cache.PurgeAll(), true
}

func (r *Router) Stats() StatsSnapshot {
	r.mu.RLock()
	totalSites := r.totalSites
	enabledSites := r.enabledSites
	r.mu.RUnlock()

	totalReq := r.totalReq.Load()
	successReq := r.successReq.Load()
	failedReq := r.failedReq.Load()
	totalLatency := r.totalLatency.Load()

	r.statsMu.RLock()
	metrics := make([]SiteMetricSnapshot, 0, len(r.siteStats))
	for _, item := range r.siteStats {
		avg := 0.0
		if item.requests > 0 {
			avg = float64(item.totalLatency) / float64(item.requests) / float64(time.Millisecond)
		}
		metrics = append(metrics, SiteMetricSnapshot{
			SiteID:           item.siteID,
			Domain:           item.domain,
			Requests:         item.requests,
			SuccessRequests:  item.success,
			FailedRequests:   item.failed,
			AverageLatencyMs: roundFloat(avg, 2),
		})
	}
	r.statsMu.RUnlock()

	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].Requests > metrics[j].Requests
	})
	if len(metrics) > 10 {
		metrics = metrics[:10]
	}

	avgLatency := 0.0
	if totalReq > 0 {
		avgLatency = float64(totalLatency) / float64(totalReq) / float64(time.Millisecond)
	}
	successRate := 0.0
	if totalReq > 0 {
		successRate = float64(successReq) / float64(totalReq) * 100
	}

	return StatsSnapshot{
		Timestamp:        time.Now().UTC(),
		TotalSites:       totalSites,
		EnabledSites:     enabledSites,
		TotalRequests:    totalReq,
		SuccessRequests:  successReq,
		FailedRequests:   failedReq,
		AverageLatencyMs: roundFloat(avgLatency, 2),
		SuccessRate:      roundFloat(successRate, 2),
		TopSites:         metrics,
	}
}

func (r *Router) RecentLogs(limit int) []AccessLogEntry {
	return r.QueryLogs(AccessLogQuery{Limit: limit})
}

func (r *Router) QueryLogs(filter AccessLogQuery) []AccessLogEntry {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}

	r.statsMu.RLock()
	store := r.logStore
	r.statsMu.RUnlock()
	if store != nil {
		return store.Query(filter)
	}

	return r.queryInMemoryLogs(filter)
}

func (r *Router) queryInMemoryLogs(filter AccessLogQuery) []AccessLogEntry {
	statusMin := filter.StatusMin
	if statusMin <= 0 {
		statusMin = 0
	}
	statusMax := filter.StatusMax
	if statusMax <= 0 {
		statusMax = 999
	}

	siteID := strings.TrimSpace(filter.SiteID)
	domain := strings.TrimSpace(filter.Domain)

	r.statsMu.RLock()
	defer r.statsMu.RUnlock()
	if len(r.logs) == 0 {
		return []AccessLogEntry{}
	}
	out := make([]AccessLogEntry, 0, minInt(filter.Limit, len(r.logs)))
	for i := len(r.logs) - 1; i >= 0 && len(out) < filter.Limit; i-- {
		entry := r.logs[i]
		if !matchAccessLog(entry, filter.From, filter.To, siteID, domain, statusMin, statusMax) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	trustedProxyRules := r.trustedProxyRulesSnapshot()
	forwardedTrusted := isForwardedHeadersTrusted(req, trustedProxyRules)
	host := normalizeRequestHost(req.Host)
	localPort := localPortFromRequest(req)
	clientIP := clientIPFromRequest(req, forwardedTrusted, trustedProxyRules)
	clientASN := clientASNFromRequest(req)
	requestScheme := schemeFromRequest(req, forwardedTrusted)
	siteCfg := r.lookupSite(host)
	if siteCfg == nil {
		siteCfg = r.lookupSiteByPort(localPort)
	}
	if siteCfg == nil {
		http.NotFound(w, req)
		r.recordAccess(nil, req, req.URL.RequestURI(), host, clientIP, "", http.StatusNotFound, "", time.Since(start), "")
		return
	}

	customPortDirectAccess := siteCfg.cfg.ListenPort > 0 && siteCfg.cfg.ListenPort == localPort
	if siteCfg.cfg.ForceHTTPS && req.TLS == nil && !customPortDirectAccess {
		http.Redirect(w, req, "https://"+host+req.URL.RequestURI(), http.StatusMovedPermanently)
		r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusMovedPermanently, "", time.Since(start), "")
		return
	}

	if deniedByPolicy(siteCfg.ipPolicy, clientIP, clientASN) {
		http.Error(w, "forbidden", http.StatusForbidden)
		r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusForbidden, "", time.Since(start), "ip access denied")
		return
	}

	// WAF: Web Application Firewall inspection (before authentication)
	if siteCfg.wafEngine != nil {
		wafResult := siteCfg.wafEngine.Inspect(req)
		if len(wafResult.Violations) > 0 {
			waf.AddViolationHeaders(w.Header(), wafResult)
			errText := "waf violation"
			if len(wafResult.Violations) > 0 {
				errText = "waf: " + string(wafResult.Violations[0].Category) + "/" + wafResult.Violations[0].RuleID
			}
			if wafResult.Blocked {
				http.Error(w, "forbidden", http.StatusForbidden)
				r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusForbidden, "", time.Since(start), errText)
				return
			}
			// In detect-only mode, just record the violation and continue
			r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusOK, "", time.Since(start), errText+"(detect)")
		}
	}

	// OAuth authentication check (session-based, redirects to login)
	if siteCfg.oauthSessionManager != nil && siteCfg.oauthProvider != nil && siteCfg.oauthConfig.Enabled {
		user := oauth.CheckAuth(siteCfg.oauthSessionManager, req)
		if user == nil || !oauth.IsAuthorized(user, siteCfg.oauthConfig) {
			isAPI := strings.Contains(req.Header.Get("Accept"), "application/json") ||
				strings.EqualFold(req.Header.Get("X-Requested-With"), "XMLHttpRequest")
			if isAPI {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusUnauthorized, "", time.Since(start), "oauth auth required")
				return
			}
			// Redirect browser requests to OAuth login
			redirectURL := fmt.Sprintf("/oauth/%s/login?redirect=%s", siteCfg.oauthProvider.Name(), url.QueryEscape(req.URL.RequestURI()))
			http.Redirect(w, req, redirectURL, http.StatusTemporaryRedirect)
			r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusTemporaryRedirect, "", time.Since(start), "oauth redirect")
			return
		}
		// Set user info headers for upstream
		req.Header.Set("X-OAuth-User", user.ID)
		req.Header.Set("X-OAuth-Email", user.Email)
		if user.Name != "" {
			req.Header.Set("X-OAuth-Name", user.Name)
		}
	}

	if siteCfg.cfg.BasicAuth.Enabled {
		if !siteCfg.authenticate(req) {
			w.Header().Set("WWW-Authenticate", `Basic realm="FlowProxy"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusUnauthorized, "", time.Since(start), "basic auth failed")
			return
		}
	}

	// JWT authentication (alternative to Basic Auth for API/bearer-token use cases)
	if siteCfg.jwtValidator != nil {
		jwtClaims, jwtErr := siteCfg.jwtValidator.Validate(req)
		if jwtErr != nil {
			w.Header().Set("WWW-Authenticate", "Bearer realm=\"FlowProxy\", error=\"invalid_token\"")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusUnauthorized, "", time.Since(start), "jwt auth: "+jwtErr.Error())
			return
		}
		if jwtClaims != nil {
			// Forward JWT claims to upstream if configured
			siteCfg.jwtValidator.ApplyForwardHeaders(req, jwtClaims)
			// Forward the raw token if configured
			if tokenStr, tokenErr := siteCfg.jwtValidator.TokenFromRequest(req); tokenErr == nil {
				siteCfg.jwtValidator.ApplyForwardToken(req, tokenStr)
			}
		}
	}

	if siteCfg.limiter != nil {
		decision := siteCfg.limiter.allow(clientIP)
		if !decision.allowed {
			if decision.blocked {
				if decision.retryAfter > 0 {
					retryAfter := int(math.Ceil(decision.retryAfter.Seconds()))
					if retryAfter < 1 {
						retryAfter = 1
					}
					w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				}
				http.Error(w, "ip blocked", http.StatusForbidden)
				r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusForbidden, "", time.Since(start), "ip auto blocked")
				return
			}
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusTooManyRequests, "", time.Since(start), "rate limit exceeded")
			return
		}
	}
	if !siteCfg.allowMethod(req.Method) {
		if len(siteCfg.allowedMethodsOrder) > 0 {
			w.Header().Set("Allow", strings.Join(siteCfg.allowedMethodsOrder, ", "))
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusMethodNotAllowed, "", time.Since(start), "method not allowed")
		return
	}
	if siteCfg.userAgentBlocked(req.UserAgent()) {
		http.Error(w, "forbidden", http.StatusForbidden)
		r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusForbidden, "", time.Since(start), "blocked user-agent")
		return
	}
	if !siteCfg.tryAcquirePerIPSlot(clientIP) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusTooManyRequests, "", time.Since(start), "per-ip concurrency limit exceeded")
		return
	}
	defer siteCfg.releasePerIPSlot(clientIP)
	if !siteCfg.tryAcquireRequestSlot() {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusTooManyRequests, "", time.Since(start), "concurrency limit exceeded")
		return
	}
	defer siteCfg.releaseRequestSlot()

	route := siteCfg.matchRoute(req)
	selectedPool := siteCfg.defaultPool
	if route.pool != nil {
		selectedPool = route.pool
	}
	if siteCfg.canary != nil && siteCfg.canary.match(req, clientIP) && siteCfg.canary.pool != nil {
		selectedPool = siteCfg.canary.pool
	}

	originalRequestURI := req.URL.RequestURI()
	requestID := newRequestID()
	originalPath := req.URL.Path
	originalRawPath := req.URL.RawPath
	rewrittenPath := route.rewritePath(req.URL.Path)
	req.URL.Path = rewrittenPath
	req.URL.RawPath = ""
	defer func() {
		req.URL.Path = originalPath
		req.URL.RawPath = originalRawPath
	}()
	if siteCfg.requestTimeout > 0 {
		timeoutCtx, cancel := context.WithTimeout(req.Context(), siteCfg.requestTimeout)
		defer cancel()
		req = req.WithContext(timeoutCtx)
	}

	siteCfg.applyRequestHeaders(req, clientIP, requestID, requestScheme, forwardedTrusted, localPort)
	req.Header.Set("X-Forwarded-Proto", requestScheme)
	req.Header.Set("X-Request-ID", requestID)

	cacheKey := ""
	if siteCfg.cache != nil && isRequestCacheable(req) {
		cacheKey = buildCacheKey(req, host, siteCfg.cacheIgnoreQuerySet)
		if cached, ok := siteCfg.cache.Get(cacheKey); ok {
			headers := cloneHTTPHeader(cached.header)
			siteCfg.applyResponseHeaders(headers, req.TLS != nil, requestID)
			writeBufferedProxyResponse(w, req, cached.status, headers, cached.body, siteCfg.compression)
			r.recordAccess(siteCfg, req, originalRequestURI, host, clientIP, "cache", cached.status, "cache://memory", time.Since(start), "")
			return
		}
	}

	attempts := selectedPool.retry.effectiveAttempts(req)
	if attempts > 1 {
		finalStatus := http.StatusBadGateway
		finalUpstream := ""
		finalResponse := newBufferedResponse()
		timedOut := false
		// Track all allocated responses for cleanup
		var prevCaptured *bufferedResponse
		for attempt := 0; attempt < attempts; attempt++ {
			// Return previous iteration's captured buffer to pool
			if prevCaptured != nil {
				putBufferedResponse(prevCaptured)
			}
			attemptTarget := selectedPool.pick(clientIP)
			if attemptTarget == nil {
				break
			}
			attemptReq := req
			if attempt > 0 {
				attemptReq = req.Clone(req.Context())
				if req.GetBody != nil {
					body, err := req.GetBody()
					if err != nil {
						break
					}
					attemptReq.Body = body
				} else if req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0 {
					attemptReq.Body = nil
				} else {
					break
				}
			}

			captured := newBufferedResponse()
			attemptTarget.active.Add(1)
			attemptTarget.proxy.ServeHTTP(captured, attemptReq)
			attemptTarget.active.Add(-1)

			statusCode := captured.Status()
			if statusCode >= 500 {
				attemptTarget.markFailure()
			} else {
				attemptTarget.markSuccess()
			}
			finalStatus = statusCode
			finalUpstream = attemptTarget.url.String()
			prevCaptured = finalResponse
			finalResponse = captured
			if !selectedPool.retry.shouldRetry(statusCode) {
				break
			}
			if attempt+1 >= attempts {
				break
			}
			delay := selectedPool.retry.backoffDelay(attempt)
			if delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
					timer.Stop()
				case <-req.Context().Done():
					timer.Stop()
					finalStatus = http.StatusGatewayTimeout
					timedOut = true
				}
				if timedOut {
					break
				}
			}
		}
		if timedOut {
			timeoutResponse := newBufferedResponse()
			timeoutResponse.WriteHeader(http.StatusGatewayTimeout)
			_, _ = timeoutResponse.Write([]byte("upstream timeout"))
			finalResponse = timeoutResponse
		}

		headers := cloneHTTPHeader(finalResponse.Header())
		body := finalResponse.Bytes()
		if cacheKey != "" && isResponseCacheable(finalStatus, headers, siteCfg.cache.policy.proactive) {
			siteCfg.cache.Set(cacheKey, finalStatus, headers, body)
		}
		siteCfg.applyResponseHeaders(headers, req.TLS != nil, requestID)
		writeBufferedProxyResponse(w, req, finalStatus, headers, body, siteCfg.compression)
		r.recordAccess(siteCfg, req, originalRequestURI, host, clientIP, "", finalStatus, finalUpstream, time.Since(start), "")
		putBufferedResponse(finalResponse)
		return
	}
	target := selectedPool.pick(clientIP)
	if target == nil {
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
		r.recordAccess(siteCfg, req, req.URL.RequestURI(), host, clientIP, "", http.StatusServiceUnavailable, "", time.Since(start), "no healthy upstream")
		return
	}

	if cacheKey != "" {
		captured := newBufferedResponse()
		target.active.Add(1)
		target.proxy.ServeHTTP(captured, req)
		target.active.Add(-1)

		statusCode := captured.Status()
		headers := cloneHTTPHeader(captured.Header())
		body := captured.Bytes()

		duration := time.Since(start)
		if statusCode >= 500 {
			target.markFailure()
		} else {
			target.markSuccess()
			if isResponseCacheable(statusCode, headers, siteCfg.cache.policy.proactive) {
				siteCfg.cache.Set(cacheKey, statusCode, headers, body)
			}
		}

		siteCfg.applyResponseHeaders(headers, req.TLS != nil, requestID)
		writeBufferedProxyResponse(w, req, statusCode, headers, body, siteCfg.compression)
		r.recordAccess(siteCfg, req, originalRequestURI, host, clientIP, target.key, statusCode, target.url.String(), duration, "")
		putBufferedResponse(captured)
		return
	}

	responseWriter := w
	var compressionWriter *compressedResponseWriter
	if !isUpgradeRequest(req.Header) {
		if algorithm := negotiateResponseCompression(req, siteCfg.compression); algorithm != compressionNone {
			compressionWriter = newCompressedResponseWriter(w, algorithm)
			responseWriter = compressionWriter
		}
	}

	recorder := &statusRecorder{
		ResponseWriter: responseWriter,
		mutate: func(headers http.Header) {
			siteCfg.applyResponseHeaders(headers, req.TLS != nil, requestID)
		},
	}

	target.active.Add(1)
	target.proxy.ServeHTTP(recorder, req)
	target.active.Add(-1)
	if compressionWriter != nil {
		_ = compressionWriter.Close()
	}

	statusCode := recorder.Status()
	duration := time.Since(start)
	if statusCode >= 500 {
		target.markFailure()
	} else {
		target.markSuccess()
	}

	r.recordAccess(siteCfg, req, originalRequestURI, host, clientIP, target.key, statusCode, target.url.String(), duration, "")
}

func (r *Router) lookupSite(host string) *compiledSite {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s, ok := r.exactHosts[host]; ok {
		return s
	}
	for _, item := range r.wildcards {
		if strings.HasSuffix(host, item.suffix) {
			return item.site
		}
	}
	return nil
}

func (r *Router) lookupSiteByPort(port int) *compiledSite {
	if port <= 0 {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.portSites[port]
}

func (r *Router) trustedProxyRulesSnapshot() []ipRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.trustedProxyRules) == 0 {
		return nil
	}
	out := make([]ipRule, len(r.trustedProxyRules))
	copy(out, r.trustedProxyRules)
	return out
}

func (r *Router) recordAccess(
	siteCfg *compiledSite,
	req *http.Request,
	requestURI string,
	host string,
	clientIP string,
	targetKey string,
	statusCode int,
	upstreamURL string,
	duration time.Duration,
	errText string,
) {
	r.totalReq.Add(1)
	if statusCode >= 200 && statusCode < 400 {
		r.successReq.Add(1)
	} else {
		r.failedReq.Add(1)
	}
	r.totalLatency.Add(uint64(duration))

	r.statsMu.Lock()

	siteID := ""
	domain := host
	if siteCfg != nil {
		siteID = siteCfg.cfg.ID
		domain = siteCfg.cfg.Domain
		if domain == "" && siteCfg.cfg.ListenPort > 0 {
			domain = fmt.Sprintf(":%d", siteCfg.cfg.ListenPort)
		}
		metric, ok := r.siteStats[siteID]
		if !ok {
			metric = &siteMetric{
				siteID: siteID,
				domain: domain,
			}
			r.siteStats[siteID] = metric
		}
		metric.requests++
		if statusCode >= 200 && statusCode < 400 {
			metric.success++
		} else {
			metric.failed++
		}
		metric.totalLatency += uint64(duration)
	}

	entry := AccessLogEntry{
		Timestamp:  time.Now().UTC(),
		SiteID:     siteID,
		Domain:     domain,
		ClientIP:   clientIP,
		Method:     req.Method,
		Path:       requestURI,
		StatusCode: statusCode,
		DurationMs: duration.Milliseconds(),
		Upstream:   upstreamURL,
		UserAgent:  req.UserAgent(),
		Error:      errText,
	}
	if targetKey != "" && entry.Upstream == "" {
		entry.Upstream = targetKey
	}

	logStore := r.logStore
	r.logs = append(r.logs, entry)
	if len(r.logs) > maxRecentLogs {
		r.logs = r.logs[len(r.logs)-maxRecentLogs:]
	}
	r.statsMu.Unlock()

	r.mu.RLock()
	alertHook := r.alertHook
	r.mu.RUnlock()
	if alertHook != nil {
		alertHook(entry)
	}
	if logStore != nil {
		logStore.Append(entry)
	}

	r.broadcastLogEntry(entry)
}

func compileSite(item site.Site) (*compiledSite, error) {
	item.Domain, item.AdditionalDomains = site.NormalizeDomains(item.Domain, item.AdditionalDomains)
	item.Upstream, item.Upstreams = site.NormalizeUpstreams(item.Upstream, item.Upstreams)
	item.Canary.Upstream, item.Canary.Upstreams = site.NormalizeUpstreams(item.Canary.Upstream, item.Canary.Upstreams)

	defaultPool, err := newUpstreamPool(item.ID, "default", item.LoadBalanceStrategy, item.Upstream, item.Upstreams, item.UpstreamTLS, item.Resilience, item.Timeouts, item.GRPC.H2C)
	if err != nil {
		return nil, err
	}

	routes := make([]compiledRoute, 0, len(item.Routes))
	for _, cfg := range item.Routes {
		cfg.Upstream, cfg.Upstreams = site.NormalizeUpstreams(cfg.Upstream, cfg.Upstreams)
		cfg.Methods = site.NormalizeHTTPMethods(cfg.Methods)
		strategy := cfg.LoadBalanceStrategy
		if strategy == "" {
			strategy = item.LoadBalanceStrategy
		}
		pool, err := newUpstreamPool(item.ID, cfg.Path, strategy, cfg.Upstream, cfg.Upstreams, item.UpstreamTLS, item.Resilience, item.Timeouts, item.GRPC.H2C)
		if err != nil {
			return nil, err
		}
		compiled := compiledRoute{
			matchType:          cfg.Match,
			path:               cfg.Path,
			methods:            methodSet(cfg.Methods),
			header:             http.CanonicalHeaderKey(strings.TrimSpace(cfg.Header)),
			headerValue:        strings.TrimSpace(cfg.HeaderValue),
			cookie:             strings.TrimSpace(cfg.Cookie),
			cookieValue:        strings.TrimSpace(cfg.CookieValue),
			query:              strings.TrimSpace(cfg.Query),
			queryValue:         strings.TrimSpace(cfg.QueryValue),
			priority:           cfg.Priority,
			rewriteReplacement: cfg.RewriteReplacement,
			pool:               pool,
		}
		if compiled.matchType == "" {
			compiled.matchType = site.MatchPrefix
		}
		if compiled.matchType == site.MatchRegex {
			reg, err := regexp.Compile(cfg.Path)
			if err != nil {
				return nil, err
			}
			compiled.pathRegex = reg
		}
		if cfg.RewritePattern != "" {
			reg, err := regexp.Compile(cfg.RewritePattern)
			if err != nil {
				return nil, err
			}
			compiled.rewriteRegex = reg
		}
		routes = append(routes, compiled)
	}

	sort.Slice(routes, func(i, j int) bool {
		if routes[i].priority != routes[j].priority {
			return routes[i].priority > routes[j].priority
		}
		return len(routes[i].path) > len(routes[j].path)
	})

	ipPolicy, err := compileIPAccessPolicy(item)
	if err != nil {
		return nil, err
	}

	var limiter *rateLimiter
	if item.RateLimit.Enabled {
		burst := float64(item.RateLimit.Burst)
		if burst <= 0 {
			burst = float64(item.RateLimit.RequestsPerMinute)
		}
		limiter = &rateLimiter{
			byIP:       map[string]*bucketState{},
			ratePerSec: float64(item.RateLimit.RequestsPerMinute) / 60.0,
			burst:      burst,
			autoBlock:  resolveAutoBlockPolicy(item.RateLimit.AutoBlock),
		}
	}
	allowedMethods := map[string]struct{}{}
	allowedMethodsOrder := site.NormalizeHTTPMethods(item.TrafficControl.AllowedMethods)
	for _, method := range allowedMethodsOrder {
		allowedMethods[method] = struct{}{}
	}
	blockedUserAgents := make([]*regexp.Regexp, 0, len(item.Security.BlockUserAgentPatterns))
	for _, rule := range item.Security.BlockUserAgentPatterns {
		pattern := strings.TrimSpace(rule)
		if pattern == "" {
			continue
		}
		reg, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		blockedUserAgents = append(blockedUserAgents, reg)
	}

	var canary *canaryRule
	if item.Canary.Enabled {
		canaryStrategy := item.Canary.LoadBalanceStrategy
		if canaryStrategy == "" {
			canaryStrategy = item.LoadBalanceStrategy
		}
		canaryPool, err := newUpstreamPool(item.ID, "canary", canaryStrategy, item.Canary.Upstream, item.Canary.Upstreams, item.UpstreamTLS, item.Resilience, item.Timeouts, item.GRPC.H2C)
		if err != nil {
			return nil, err
		}
		canary = &canaryRule{
			pool:        canaryPool,
			header:      http.CanonicalHeaderKey(strings.TrimSpace(item.Canary.Header)),
			headerValue: strings.TrimSpace(item.Canary.HeaderValue),
			cookie:      strings.TrimSpace(item.Canary.Cookie),
			cookieValue: strings.TrimSpace(item.Canary.CookieValue),
			weight:      item.Canary.Weight,
		}
	}
	requestTimeout := durationFromMillis(item.Timeouts.RequestMillis)
	cacheIgnoreQuerySet := make(map[string]struct{}, len(item.Cache.KeyIgnoreQueryParams))
	for _, key := range site.NormalizeQueryKeys(item.Cache.KeyIgnoreQueryParams) {
		cacheIgnoreQuerySet[key] = struct{}{}
	}

	var jwtValidator *jwtauth.Validator
	if item.JWT.Enabled {
		var jwtErr error
		jwtValidator, jwtErr = jwtauth.NewValidator(context.Background(), jwtauth.Config{
			Enabled:          item.JWT.Enabled,
			ExtractFrom:      item.JWT.ExtractFrom,
			ExtractName:      item.JWT.ExtractName,
			SigningAlgorithm: item.JWT.SigningAlgorithm,
			HMACSecret:       item.JWT.HMACSecret,
			JWKSURL:          item.JWT.JWKSURL,
			JWKSRefreshSec:   item.JWT.JWKSRefreshSec,
			Issuer:           item.JWT.Issuer,
			Audience:         item.JWT.Audience,
			ForwardToken:     item.JWT.ForwardToken,
		})
		if jwtErr != nil {
			return nil, fmt.Errorf("site %s jwt validator: %w", item.ID, jwtErr)
		}
	}

	var oauthSessionManager *oauth.SessionManager
	var oauthProvider oauth.Provider
	var oauthSiteConfig oauth.SiteConfig
	if item.OAuth.Enabled {
		oauthSiteConfig = oauth.SiteConfig{
			Enabled:        item.OAuth.Enabled,
			Provider:       item.OAuth.Provider,
			ClientID:       item.OAuth.ClientID,
			ClientSecret:   item.OAuth.ClientSecret,
			Scopes:         item.OAuth.Scopes,
			AllowedDomains: item.OAuth.AllowedDomains,
			AllowedEmails:  item.OAuth.AllowedEmails,
			CallbackURL:    item.OAuth.CallbackURL,
		}
		// Use a global session manager secret - in production, configure via settings
		sm := oauth.NewSessionManager("flowproxy-oauth-secret-change-me", 24*time.Hour)
		oauthSessionManager = sm

		providerType := oauth.ProviderType(strings.ToLower(strings.TrimSpace(item.OAuth.Provider)))
		if providerType == "" {
			providerType = oauth.ProviderGeneric
		}
		provider, pErr := oauth.NewProvider(oauth.ProviderConfig{
			Type:         providerType,
			ClientID:     item.OAuth.ClientID,
			ClientSecret: item.OAuth.ClientSecret,
			Scopes:       item.OAuth.Scopes,
			RedirectURL:  item.OAuth.CallbackURL,
		})
		if pErr != nil {
			return nil, fmt.Errorf("site %s oauth provider: %w", item.ID, pErr)
		}
		oauthProvider = provider
	}

	var wafEngine *waf.Engine
	if item.WAF.Enabled {
		var wafErr error
		wafEngine, wafErr = waf.NewEngine(waf.Config{
			Enabled:           item.WAF.Enabled,
			Mode:              item.WAF.Mode,
			SeverityThreshold: item.WAF.SeverityThreshold,
			ExcludePaths:      item.WAF.ExcludePaths,
		})
		if wafErr != nil {
			return nil, fmt.Errorf("site %s waf engine: %w", item.ID, wafErr)
		}
	}

	return &compiledSite{
		cfg:                   item,
		defaultPool:           defaultPool,
		canary:                canary,
		routes:                routes,
		cache:                 newResponseCache(resolveCachePolicy(item.Cache)),
		compression:           resolveCompressionPolicy(item.Gzip, item.Brotli),
		requestHeaders:        cloneHeaders(item.RequestHeaders),
		responseHeaders:       cloneHeaders(item.ResponseHeaders),
		removeRequestHeaders:  canonicalHeaderList(item.RemoveRequestHeaders),
		removeResponseHeaders: canonicalHeaderList(item.RemoveResponseHeaders),
		autoRequestHeaders:    item.AutoRequestHeaders,
		autoResponseHeaders:   item.AutoResponseHeaders,
		cacheIgnoreQuerySet:   cacheIgnoreQuerySet,
		requestTimeout:        requestTimeout,
		ipPolicy:              ipPolicy,
		limiter:               limiter,
		allowedMethods:        allowedMethods,
		allowedMethodsOrder:   allowedMethodsOrder,
		blockedUserAgents:     blockedUserAgents,
		maxConcurrent:         int64(item.TrafficControl.MaxConcurrentRequests),
		maxConcurrentPerIP:    int64(item.TrafficControl.MaxConcurrentPerIP),
		perIPRequests:         map[string]*atomic.Int64{},
		jwtValidator:          jwtValidator,
		wafEngine:             wafEngine,
		oauthSessionManager:   oauthSessionManager,
		oauthConfig:           oauthSiteConfig,
		oauthProvider:         oauthProvider,
	}, nil
}

func newUpstreamPool(
	siteID string,
	routeKey string,
	strategy string,
	fallback string,
	upstreams []site.Upstream,
	upstreamTLS site.UpstreamTLSConfig,
	resilience site.ResilienceConfig,
	timeouts site.TimeoutConfig,
	grpcH2C bool,
) (*upstreamPool, error) {
	if strategy == "" {
		strategy = site.LoadBalanceRound
	}

	raw := make([]site.Upstream, 0, len(upstreams)+1)
	seen := map[string]struct{}{}
	if fallback != "" {
		fallback = strings.TrimSpace(fallback)
		if fallback != "" {
			raw = append(raw, site.Upstream{URL: fallback, Weight: 1})
			seen[fallback] = struct{}{}
		}
	}
	for _, upstream := range upstreams {
		key := strings.TrimSpace(upstream.URL)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		raw = append(raw, upstream)
	}

	targets := make([]*upstreamTarget, 0, len(raw))
	for _, item := range raw {
		if strings.TrimSpace(item.URL) == "" {
			continue
		}
		u, err := url.Parse(item.URL)
		if err != nil {
			return nil, err
		}
		weight := item.Weight
		if weight <= 0 {
			weight = 1
		}
		transport, err := newUpstreamTransport(u, upstreamTLS, timeouts, grpcH2C)
		if err != nil {
			return nil, err
		}
		target := &upstreamTarget{
			key:       item.URL,
			url:       u,
			weight:    weight,
			transport: transport,
			health:    resolveActiveHealthPolicy(resilience.ActiveHealthCheck),
			circuit:   resolveCircuitBreakerPolicy(resilience.CircuitBreaker),
		}
		target.proxy = newReverseProxy(target, transport)
		targets = append(targets, target)
	}
	if len(targets) == 0 {
		return nil, errorsf("site %s has no usable upstream", siteID)
	}

	pool := &upstreamPool{
		name:     routeKey,
		strategy: strategy,
		targets:  targets,
		retry:    resolveRetryPolicy(resilience.Retry),
	}
	if strategy == site.LoadBalanceWeight {
		pool.weightedPlan = buildWeightedPlan(targets)
	}
	return pool, nil
}

func buildWeightedPlan(targets []*upstreamTarget) []int {
	plan := make([]int, 0)
	for i, target := range targets {
		weight := target.weight
		if weight > 20 {
			weight = 20
		}
		for n := 0; n < weight; n++ {
			plan = append(plan, i)
		}
	}
	if len(plan) == 0 {
		for i := range targets {
			plan = append(plan, i)
		}
	}
	return plan
}

func newReverseProxy(target *upstreamTarget, transport http.RoundTripper) *httputil.ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(target.url)
	if transport != nil {
		rp.Transport = transport
	}
	original := rp.Director
	rp.Director = grpcDirector(func(req *http.Request) {
		host := req.Host
		scheme := "http"
		if req.TLS != nil {
			scheme = "https"
		} else if xfp := normalizeForwardedProto(req.Header.Get("X-Forwarded-Proto")); xfp != "" {
			scheme = xfp
		}
		original(req)
		if !IsGRPCRequest(req) {
			req.Header.Set("X-Forwarded-Host", host)
			req.Header.Set("X-Forwarded-Proto", scheme)
		}
	})
	rp.ErrorHandler = grpcErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
		status := http.StatusBadGateway
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			status = http.StatusGatewayTimeout
		}
		http.Error(w, "upstream unavailable", status)
	})
	return rp
}

func (c *compiledSite) matchRoute(req *http.Request) compiledRoute {
	for _, route := range c.routes {
		if route.matches(req) {
			return route
		}
	}
	return compiledRoute{}
}

func (c *compiledSite) applyRequestHeaders(
	req *http.Request,
	clientIP string,
	requestID string,
	requestScheme string,
	forwardedTrusted bool,
	requestLocalPort int,
) {
	removed := map[string]struct{}{}
	for _, key := range c.removeRequestHeaders {
		removed[key] = struct{}{}
	}
	if c.autoRequestHeaders {
		// Drop untrusted forwarded chain to avoid spoofed XFF reaching upstream.
		if !forwardedTrusted {
			if _, blocked := removed["X-Forwarded-For"]; !blocked {
				req.Header.Del("X-Forwarded-For")
			}
		}
		setRequestHeaderIfAllowed(req.Header, removed, "X-Real-IP", clientIP)
		setRequestHeaderIfAllowed(req.Header, removed, "X-Forwarded-Port", forwardedPortValue(req, requestScheme, requestLocalPort))
		setRequestHeaderIfAllowed(req.Header, removed, "X-Request-ID", requestID)
	}
	for _, key := range c.removeRequestHeaders {
		req.Header.Del(key)
	}
	for _, header := range c.requestHeaders {
		value := expandHeaderValue(header.Value, req, clientIP, requestID, requestScheme)
		req.Header.Set(header.Name, value)
	}
}

func (c *compiledSite) applyResponseHeaders(headers http.Header, tlsRequest bool, requestID string) {
	headers.Set("X-Proxy-By", "FlowProxy")
	removed := map[string]struct{}{}
	for _, key := range c.removeResponseHeaders {
		headers.Del(key)
		removed[key] = struct{}{}
	}
	if c.autoResponseHeaders {
		setHeaderIfAllowed(headers, removed, "X-Request-ID", requestID)
	}
	if c.cfg.Security.EnableSecurityHeaders {
		setSecurityHeaderIfAllowed(headers, removed, "X-Content-Type-Options", "nosniff")
		setSecurityHeaderIfAllowed(headers, removed, "X-Frame-Options", "SAMEORIGIN")
		setSecurityHeaderIfAllowed(headers, removed, "Referrer-Policy", "strict-origin-when-cross-origin")
		setSecurityHeaderIfAllowed(headers, removed, "X-XSS-Protection", "1; mode=block")
		setSecurityHeaderIfAllowed(headers, removed, "Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		setSecurityHeaderIfAllowed(headers, removed, "Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'self'")
		if tlsRequest {
			setSecurityHeaderIfAllowed(headers, removed, "Strict-Transport-Security", defaultHSTSValue)
		}
	}
	for _, header := range c.responseHeaders {
		headers.Set(header.Name, header.Value)
	}
}

func (c *compiledSite) allowMethod(method string) bool {
	if len(c.allowedMethods) == 0 {
		return true
	}
	_, ok := c.allowedMethods[strings.ToUpper(strings.TrimSpace(method))]
	return ok
}

func (c *compiledSite) userAgentBlocked(userAgent string) bool {
	for _, pattern := range c.blockedUserAgents {
		if pattern.MatchString(userAgent) {
			return true
		}
	}
	return false
}

func (c *compiledSite) tryAcquireRequestSlot() bool {
	if c.maxConcurrent <= 0 {
		return true
	}
	for {
		current := c.activeRequests.Load()
		if current >= c.maxConcurrent {
			return false
		}
		if c.activeRequests.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (c *compiledSite) releaseRequestSlot() {
	if c.maxConcurrent <= 0 {
		return
	}
	c.activeRequests.Add(-1)
}

func (c *compiledSite) tryAcquirePerIPSlot(ip string) bool {
	if c.maxConcurrentPerIP <= 0 {
		return true
	}
	c.perIPMu.Lock()
	defer c.perIPMu.Unlock()
	counter, ok := c.perIPRequests[ip]
	if !ok {
		counter = &atomic.Int64{}
		c.perIPRequests[ip] = counter
	}
	current := counter.Load()
	if current >= c.maxConcurrentPerIP {
		return false
	}
	counter.Add(1)
	return true
}

func (c *compiledSite) releasePerIPSlot(ip string) {
	if c.maxConcurrentPerIP <= 0 {
		return
	}
	c.perIPMu.Lock()
	defer c.perIPMu.Unlock()
	counter, ok := c.perIPRequests[ip]
	if !ok {
		return
	}
	current := counter.Add(-1)
	if current <= 0 {
		delete(c.perIPRequests, ip)
	}
}

func (c *compiledSite) authenticate(req *http.Request) bool {
	user, pass, ok := req.BasicAuth()
	if !ok {
		return false
	}
	usernameMatch := subtle.ConstantTimeCompare([]byte(user), []byte(c.cfg.BasicAuth.Username)) == 1
	if !usernameMatch {
		return false
	}

	if c.cfg.BasicAuth.PasswordHash != "" {
		return bcrypt.CompareHashAndPassword([]byte(c.cfg.BasicAuth.PasswordHash), []byte(pass)) == nil
	}
	if c.cfg.BasicAuth.Password != "" {
		return subtle.ConstantTimeCompare([]byte(pass), []byte(c.cfg.BasicAuth.Password)) == 1
	}
	return false
}

func (r compiledRoute) matches(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	path := req.URL.Path
	switch r.matchType {
	case site.MatchExact:
		if path != r.path {
			return false
		}
	case site.MatchRegex:
		if r.pathRegex == nil || !r.pathRegex.MatchString(path) {
			return false
		}
	default:
		if !strings.HasPrefix(path, r.path) {
			return false
		}
	}
	if len(r.methods) > 0 {
		method := strings.ToUpper(strings.TrimSpace(req.Method))
		if _, ok := r.methods[method]; !ok {
			return false
		}
	}
	if r.header != "" {
		value := strings.TrimSpace(req.Header.Get(r.header))
		if value == "" {
			return false
		}
		if r.headerValue != "" && value != r.headerValue {
			return false
		}
	}
	if r.cookie != "" {
		cookie, err := req.Cookie(r.cookie)
		if err != nil {
			return false
		}
		value := strings.TrimSpace(cookie.Value)
		if value == "" {
			return false
		}
		if r.cookieValue != "" && value != r.cookieValue {
			return false
		}
	}
	if r.query != "" {
		value := strings.TrimSpace(req.URL.Query().Get(r.query))
		if value == "" {
			return false
		}
		if r.queryValue != "" && value != r.queryValue {
			return false
		}
	}
	return true
}

func (r compiledRoute) rewritePath(path string) string {
	if r.rewriteRegex == nil {
		return path
	}
	out := r.rewriteRegex.ReplaceAllString(path, r.rewriteReplacement)
	if out == "" {
		return "/"
	}
	if strings.HasPrefix(out, "/") {
		return out
	}
	return "/" + out
}

func (p *upstreamPool) pick(clientIP string) *upstreamTarget {
	healthy := p.healthyTargets()
	if len(healthy) == 0 {
		if len(p.targets) == 1 {
			return p.targets[0]
		}
		return nil
	}

	switch p.strategy {
	case site.LoadBalanceRandom:
		return healthy[mathrand.Intn(len(healthy))]
	case site.LoadBalanceIPHash:
		idx := int(hashText(clientIP) % uint64(len(healthy)))
		return healthy[idx]
	case site.LoadBalanceLeast:
		selected := healthy[0]
		minActive := selected.active.Load()
		for _, item := range healthy[1:] {
			if active := item.active.Load(); active < minActive {
				minActive = active
				selected = item
			}
		}
		return selected
	case site.LoadBalanceWeight:
		return p.weightedPick(healthy)
	default:
		idx := p.rrCounter.Add(1)
		return healthy[int(idx-1)%len(healthy)]
	}
}

func (p *upstreamPool) weightedPick(healthy []*upstreamTarget) *upstreamTarget {
	if len(healthy) == len(p.targets) && len(p.weightedPlan) > 0 {
		idx := p.rrCounter.Add(1)
		targetIndex := p.weightedPlan[int(idx-1)%len(p.weightedPlan)]
		return p.targets[targetIndex]
	}
	totalWeight := 0
	for _, item := range healthy {
		totalWeight += item.weight
	}
	if totalWeight <= 0 {
		return healthy[mathrand.Intn(len(healthy))]
	}
	n := mathrand.Intn(totalWeight)
	for _, item := range healthy {
		if n < item.weight {
			return item
		}
		n -= item.weight
	}
	return healthy[len(healthy)-1]
}

func (p *upstreamPool) healthyTargets() []*upstreamTarget {
	now := time.Now().UnixNano()
	// Fast path: check if all targets are healthy (common case)
	allHealthy := true
	for _, item := range p.targets {
		until := item.unhealthyUntil.Load()
		if until > now {
			allHealthy = false
			break
		}
		if item.circuit.enabled && item.cbOpenUntil.Load() > now {
			allHealthy = false
			break
		}
	}
	if allHealthy {
		return p.targets
	}
	// Slow path: filter out unhealthy targets
	out := make([]*upstreamTarget, 0, len(p.targets))
	for _, item := range p.targets {
		until := item.unhealthyUntil.Load()
		if until > now {
			continue
		}
		if item.circuit.enabled && item.cbOpenUntil.Load() > now {
			continue
		}
		out = append(out, item)
	}
	return out
}

func (u *upstreamTarget) markFailure() {
	failures := u.failures.Add(1)
	if failures >= passiveFailThreshold {
		u.unhealthyUntil.Store(time.Now().Add(passiveRecoverWindow).UnixNano())
		u.failures.Store(0)
	}
	if u.circuit.enabled {
		cb := u.cbFailures.Add(1)
		if cb >= u.circuit.failureThreshold {
			u.cbOpenUntil.Store(time.Now().Add(u.circuit.openDuration).UnixNano())
			u.cbFailures.Store(0)
		}
	}
}

func (u *upstreamTarget) markSuccess() {
	u.failures.Store(0)
	u.unhealthyUntil.Store(0)
	u.cbFailures.Store(0)
	u.cbOpenUntil.Store(0)
}

func resolveCachePolicy(cfg site.CacheConfig) cachePolicy {
	if !cfg.Enabled {
		return cachePolicy{}
	}
	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	maxEntries := cfg.MaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultCacheMaxEntries
	}
	maxBodyBytes := cfg.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultCacheMaxBodyBytes
	}
	return cachePolicy{
		enabled:      true,
		ttl:          ttl,
		maxEntries:   maxEntries,
		maxBodyBytes: maxBodyBytes,
		proactive:    cfg.Proactive,
	}
}

func resolveCompressionPolicy(gzipCfg site.GzipConfig, brotliCfg site.BrotliConfig) compressionPolicy {
	return compressionPolicy{
		gzipEnabled:   gzipCfg.Enabled,
		brotliEnabled: brotliCfg.Enabled,
	}
}

func newResponseCache(policy cachePolicy) *responseCache {
	if !policy.enabled {
		return nil
	}
	return &responseCache{
		entries: make(map[string]*cacheEntry),
		lruList: list.New(),
		policy:  policy,
	}
}

func (c *responseCache) Get(key string) (cacheEntry, bool) {
	if c == nil || key == "" {
		return cacheEntry{}, false
	}
	now := time.Now()
	c.mu.Lock()

	entry, ok := c.entries[key]
	if !ok {
		c.mu.Unlock()
		return cacheEntry{}, false
	}
	if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
		c.lruList.Remove(entry.lruElem)
		delete(c.entries, key)
		c.mu.Unlock()
		return cacheEntry{}, false
	}
	// Move to front for LRU
	c.lruList.MoveToFront(entry.lruElem)
	c.mu.Unlock()

	return cacheEntry{
		status:    entry.status,
		header:    cloneHTTPHeader(entry.header),
		body:      append([]byte(nil), entry.body...),
		expiresAt: entry.expiresAt,
	}, true
}

func (c *responseCache) Set(key string, status int, header http.Header, body []byte) {
	if c == nil || key == "" {
		return
	}
	if len(body) > c.policy.maxBodyBytes {
		return
	}

	now := time.Now()
	expiresAt := now.Add(c.policy.ttl)
	c.mu.Lock()
	defer c.mu.Unlock()

	// Lazy expiry: check if this key already exists
	if existing, ok := c.entries[key]; ok {
		c.lruList.Remove(existing.lruElem)
		delete(c.entries, key)
	}

	// Evict expired entries (sampling approach: check up to 10 random entries)
	evicted := 0
	for key, entry := range c.entries {
		if evicted >= 10 {
			break
		}
		if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
			c.lruList.Remove(entry.lruElem)
			delete(c.entries, key)
			evicted++
		}
	}

	// Evict LRU entries if over capacity
	for len(c.entries) >= c.policy.maxEntries {
		back := c.lruList.Back()
		if back == nil {
			break
		}
		lk, ok := back.Value.(lruKey)
		if !ok {
			break
		}
		delete(c.entries, lk.key)
		c.lruList.Remove(back)
	}

	// Insert new entry at front
	elem := c.lruList.PushFront(lruKey{key: key})
	c.entries[key] = &cacheEntry{
		status:    status,
		header:    cloneHTTPHeader(header),
		body:      append([]byte(nil), body...),
		expiresAt: expiresAt,
		lruElem:   elem,
	}
}

func (c *responseCache) PurgeAll() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	count := len(c.entries)
	if count == 0 {
		return 0
	}
	c.entries = make(map[string]*cacheEntry)
	c.lruList.Init()
	return count
}

func isRequestCacheable(req *http.Request) bool {
	if req == nil {
		return false
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	if isUpgradeRequest(req.Header) {
		return false
	}
	if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
		return false
	}
	if req.Header.Get("Range") != "" {
		return false
	}
	return true
}

func isResponseCacheable(statusCode int, headers http.Header, proactive bool) bool {
	if statusCode != http.StatusOK {
		return false
	}
	if len(headers.Values("Set-Cookie")) > 0 {
		return false
	}

	cacheControl := strings.ToLower(strings.TrimSpace(headers.Get("Cache-Control")))
	if strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "private") {
		return false
	}

	vary := strings.TrimSpace(headers.Get("Vary"))
	if vary != "" {
		parts := strings.Split(vary, ",")
		for _, item := range parts {
			field := strings.ToLower(strings.TrimSpace(item))
			if field == "" {
				continue
			}
			if field == "*" || field != "accept-encoding" {
				return false
			}
		}
	}
	if proactive {
		return true
	}
	if maxAge, ok := parseCacheControlMaxAge(cacheControl); ok && maxAge > 0 {
		return true
	}
	if hasPublicCacheControl(cacheControl) {
		return true
	}
	if expires := strings.TrimSpace(headers.Get("Expires")); expires != "" {
		if t, err := http.ParseTime(expires); err == nil && t.After(time.Now()) {
			return true
		}
	}
	return false
}

func parseCacheControlMaxAge(cacheControl string) (int, bool) {
	if cacheControl == "" {
		return 0, false
	}
	parts := strings.Split(cacheControl, ",")
	for _, part := range parts {
		token := strings.TrimSpace(strings.ToLower(part))
		if token == "" {
			continue
		}
		if !strings.Contains(token, "=") {
			continue
		}
		kv := strings.SplitN(token, "=", 2)
		key := strings.TrimSpace(kv[0])
		if key != "max-age" && key != "s-maxage" {
			continue
		}
		raw := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		n, err := strconv.Atoi(raw)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func hasPublicCacheControl(cacheControl string) bool {
	if cacheControl == "" {
		return false
	}
	parts := strings.Split(cacheControl, ",")
	for _, part := range parts {
		if strings.TrimSpace(strings.ToLower(part)) == "public" {
			return true
		}
	}
	return false
}

func buildCacheKey(req *http.Request, host string, ignoreQuery map[string]struct{}) string {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	uri := "/"
	if req.URL != nil {
		uri = buildCacheURI(req.URL, ignoreQuery)
	}
	if uri == "" {
		uri = "/"
	}
	acceptEncoding := normalizeAcceptEncodingForCache(req.Header.Get("Accept-Encoding"))
	return method + "|" + strings.ToLower(strings.TrimSpace(host)) + "|" + uri + "|ae=" + acceptEncoding
}

func buildCacheURI(u *url.URL, ignoreQuery map[string]struct{}) string {
	if u == nil {
		return "/"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	rawQuery := strings.TrimSpace(u.RawQuery)
	if rawQuery == "" || len(ignoreQuery) == 0 {
		if rawQuery == "" {
			return path
		}
		return path + "?" + rawQuery
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return path + "?" + rawQuery
	}
	for key := range values {
		if _, ok := ignoreQuery[strings.ToLower(strings.TrimSpace(key))]; ok {
			delete(values, key)
		}
	}
	encoded := values.Encode()
	if encoded == "" {
		return path
	}
	return path + "?" + encoded
}

func normalizeAcceptEncodingForCache(raw string) string {
	parts := strings.Split(raw, ",")
	seen := map[string]struct{}{}
	values := make([]string, 0, len(parts))
	for _, item := range parts {
		token := strings.ToLower(strings.TrimSpace(strings.SplitN(item, ";", 2)[0]))
		if token == "" {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		values = append(values, token)
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func writeBufferedProxyResponse(w http.ResponseWriter, req *http.Request, statusCode int, headers http.Header, body []byte, policy compressionPolicy) {
	copyHeader(w.Header(), headers)
	if strings.EqualFold(req.Method, http.MethodHead) {
		w.WriteHeader(statusCode)
		return
	}
	algorithm := negotiateResponseCompression(req, policy)
	if algorithm != compressionNone && shouldCompressResponse(statusCode, w.Header()) {
		appendVaryHeader(w.Header(), "Accept-Encoding")
		w.Header().Set("Content-Encoding", string(algorithm))
		w.Header().Del("Content-Length")
		w.WriteHeader(statusCode)
		writer, _ := newCompressionWriter(w, algorithm)
		if writer != nil {
			_, _ = writer.Write(body)
			_ = writer.Close()
			return
		}
		_, _ = w.Write(body)
		return
	}
	w.WriteHeader(statusCode)
	_, _ = w.Write(body)
}

func negotiateResponseCompression(req *http.Request, policy compressionPolicy) compressionAlgorithm {
	if req == nil {
		return compressionNone
	}
	if !policy.gzipEnabled && !policy.brotliEnabled {
		return compressionNone
	}
	weights := parseAcceptEncodingWeights(req.Header.Get("Accept-Encoding"))
	if !weights.hasHeader {
		return compressionNone
	}
	gzipQuality := 0.0
	if policy.gzipEnabled {
		gzipQuality = weights.quality("gzip")
	}
	brotliQuality := 0.0
	if policy.brotliEnabled {
		brotliQuality = weights.quality("br")
	}
	if brotliQuality <= 0 && gzipQuality <= 0 {
		return compressionNone
	}
	if brotliQuality >= gzipQuality && brotliQuality > 0 {
		return compressionBrotli
	}
	if gzipQuality > 0 {
		return compressionGzip
	}
	return compressionNone
}

type acceptEncodingWeights struct {
	hasHeader   bool
	wildcardQ   float64
	hasWildcard bool
	explicitQ   map[string]float64
}

func parseAcceptEncodingWeights(raw string) acceptEncodingWeights {
	result := acceptEncodingWeights{
		hasHeader: strings.TrimSpace(raw) != "",
		explicitQ: map[string]float64{},
	}
	if !result.hasHeader {
		return result
	}
	parts := strings.Split(raw, ",")
	for _, item := range parts {
		token := strings.TrimSpace(item)
		if token == "" {
			continue
		}
		segments := strings.Split(token, ";")
		name := strings.ToLower(strings.TrimSpace(segments[0]))
		if name == "" {
			continue
		}
		q := 1.0
		for _, segment := range segments[1:] {
			kv := strings.SplitN(strings.TrimSpace(segment), "=", 2)
			if len(kv) != 2 || strings.ToLower(strings.TrimSpace(kv[0])) != "q" {
				continue
			}
			v, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64)
			if err == nil {
				q = v
			}
		}
		if q < 0 {
			q = 0
		}
		if q > 1 {
			q = 1
		}
		if name == "*" {
			if !result.hasWildcard || q > result.wildcardQ {
				result.wildcardQ = q
				result.hasWildcard = true
			}
			continue
		}
		if current, ok := result.explicitQ[name]; !ok || q > current {
			result.explicitQ[name] = q
		}
	}
	return result
}

func (w acceptEncodingWeights) quality(name string) float64 {
	if name == "" {
		return 0
	}
	key := strings.ToLower(strings.TrimSpace(name))
	if q, ok := w.explicitQ[key]; ok {
		return q
	}
	if w.hasWildcard {
		return w.wildcardQ
	}
	return 0
}

func shouldCompressResponse(statusCode int, headers http.Header) bool {
	if statusCode < 200 || statusCode == http.StatusNoContent || statusCode == http.StatusNotModified {
		return false
	}
	if strings.TrimSpace(headers.Get("Content-Encoding")) != "" {
		return false
	}
	if strings.TrimSpace(headers.Get("Content-Range")) != "" {
		return false
	}
	contentType := strings.ToLower(strings.TrimSpace(headers.Get("Content-Type")))
	if contentType == "" {
		return true
	}
	return strings.HasPrefix(contentType, "text/") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "xml") ||
		strings.Contains(contentType, "svg")
}

func appendVaryHeader(headers http.Header, field string) {
	value := strings.TrimSpace(field)
	if value == "" {
		return
	}
	current := headers.Values("Vary")
	if len(current) == 0 {
		headers.Set("Vary", value)
		return
	}
	parts := strings.Split(strings.Join(current, ","), ",")
	for _, item := range parts {
		if strings.EqualFold(strings.TrimSpace(item), value) {
			return
		}
	}
	headers.Set("Vary", strings.Join(append(parts, value), ","))
}

func cloneHTTPHeader(src http.Header) http.Header {
	out := make(http.Header, len(src))
	for key, values := range src {
		dup := make([]string, len(values))
		copy(dup, values)
		out[key] = dup
	}
	return out
}

type compressedResponseWriter struct {
	http.ResponseWriter
	algorithm   compressionAlgorithm
	encoder     io.WriteCloser
	flushFn     func() error
	compress    bool
	wroteHeader bool
}

func newCompressionWriter(w io.Writer, algorithm compressionAlgorithm) (io.WriteCloser, func() error) {
	switch algorithm {
	case compressionGzip:
		writer := gzip.NewWriter(w)
		return writer, writer.Flush
	case compressionBrotli:
		writer := brotli.NewWriter(w)
		return writer, writer.Flush
	default:
		return nil, nil
	}
}

func newCompressedResponseWriter(w http.ResponseWriter, algorithm compressionAlgorithm) *compressedResponseWriter {
	return &compressedResponseWriter{
		ResponseWriter: w,
		algorithm:      algorithm,
	}
}

func (w *compressedResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}
	w.wroteHeader = true
	headers := w.ResponseWriter.Header()
	if shouldCompressResponse(statusCode, headers) {
		w.compress = true
		appendVaryHeader(headers, "Accept-Encoding")
		headers.Set("Content-Encoding", string(w.algorithm))
		headers.Del("Content-Length")
	}
	w.ResponseWriter.WriteHeader(statusCode)
	if w.compress {
		w.encoder, w.flushFn = newCompressionWriter(w.ResponseWriter, w.algorithm)
		if w.encoder == nil {
			w.compress = false
		}
	}
}

func (w *compressedResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if !w.compress {
		return w.ResponseWriter.Write(data)
	}
	return w.encoder.Write(data)
}

func (w *compressedResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.compress && w.flushFn != nil {
		_ = w.flushFn()
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *compressedResponseWriter) ReadFrom(reader io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if !w.compress {
		if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
			return rf.ReadFrom(reader)
		}
		return io.Copy(w.ResponseWriter, reader)
	}
	return io.Copy(w.encoder, reader)
}

func (w *compressedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	return hj.Hijack()
}

func (w *compressedResponseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *compressedResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *compressedResponseWriter) Close() error {
	if w.encoder != nil {
		return w.encoder.Close()
	}
	return nil
}

func parseIPRules(raw []string) ([]ipRule, error) {
	out := make([]ipRule, 0, len(raw))
	for _, item := range raw {
		candidate := strings.TrimSpace(item)
		if candidate == "" {
			continue
		}
		if strings.Contains(candidate, "/") {
			_, network, err := net.ParseCIDR(candidate)
			if err != nil {
				return nil, err
			}
			out = append(out, ipRule{net: network})
			continue
		}
		ip := net.ParseIP(candidate)
		if ip == nil {
			return nil, fmt.Errorf("invalid ip: %s", candidate)
		}
		out = append(out, ipRule{ip: ip})
	}
	return out, nil
}

func compileIPAccessPolicy(item site.Site) (compiledIPAccessPolicy, error) {
	sources := make([]compiledIPAccessSource, 0, len(item.IPAccessPolicy.SourceOrder))
	anyAllow := false
	if len(item.IPAccessPolicy.SourceOrder) > 0 && len(item.IPAccessPolicy.Sources) > 0 {
		sourceMap := make(map[string]site.IPAccessSourceRules, len(item.IPAccessPolicy.Sources))
		for _, source := range item.IPAccessPolicy.Sources {
			key := strings.ToLower(strings.TrimSpace(source.Source))
			if key == "" {
				continue
			}
			sourceMap[key] = source
		}
		for _, sourceName := range item.IPAccessPolicy.SourceOrder {
			key := strings.ToLower(strings.TrimSpace(sourceName))
			if key == "" {
				continue
			}
			source, ok := sourceMap[key]
			if !ok {
				continue
			}
			allow, err := parseIPRules(source.AllowCIDRs)
			if err != nil {
				return compiledIPAccessPolicy{}, fmt.Errorf("ip access source %s allow rules: %w", key, err)
			}
			deny, err := parseIPRules(source.DenyCIDRs)
			if err != nil {
				return compiledIPAccessPolicy{}, fmt.Errorf("ip access source %s deny rules: %w", key, err)
			}
			allowASNs, err := parseASNRules(source.AllowASNs)
			if err != nil {
				return compiledIPAccessPolicy{}, fmt.Errorf("ip access source %s allow asn rules: %w", key, err)
			}
			denyASNs, err := parseASNRules(source.DenyASNs)
			if err != nil {
				return compiledIPAccessPolicy{}, fmt.Errorf("ip access source %s deny asn rules: %w", key, err)
			}
			denyReputation, err := parseIPRules(source.DenyReputationCIDRs)
			if err != nil {
				return compiledIPAccessPolicy{}, fmt.Errorf("ip access source %s deny reputation rules: %w", key, err)
			}
			if len(allow) > 0 || len(allowASNs) > 0 {
				anyAllow = true
			}
			allowFirst := normalizeRuntimeConflictPolicy(source.ConflictPolicy) == settings.IPRuleConflictAllowFirst
			sources = append(sources, compiledIPAccessSource{
				source:         key,
				allowFirst:     allowFirst,
				allow:          allow,
				deny:           deny,
				allowASNs:      allowASNs,
				denyASNs:       denyASNs,
				denyReputation: denyReputation,
			})
		}
	}
	if len(sources) == 0 {
		allow, err := parseIPRules(item.IPAccess.AllowCIDRs)
		if err != nil {
			return compiledIPAccessPolicy{}, err
		}
		deny, err := parseIPRules(item.IPAccess.DenyCIDRs)
		if err != nil {
			return compiledIPAccessPolicy{}, err
		}
		allowASNs, err := parseASNRules(item.IPAccess.AllowASNs)
		if err != nil {
			return compiledIPAccessPolicy{}, err
		}
		denyASNs, err := parseASNRules(item.IPAccess.DenyASNs)
		if err != nil {
			return compiledIPAccessPolicy{}, err
		}
		denyReputation, err := parseIPRules(item.IPAccess.DenyReputationCIDRs)
		if err != nil {
			return compiledIPAccessPolicy{}, err
		}
		anyAllow = len(allow) > 0 || len(allowASNs) > 0
		sources = append(sources, compiledIPAccessSource{
			source:         "legacy",
			allowFirst:     false,
			allow:          allow,
			deny:           deny,
			allowASNs:      allowASNs,
			denyASNs:       denyASNs,
			denyReputation: denyReputation,
		})
	}
	return compiledIPAccessPolicy{
		sources:  sources,
		anyAllow: anyAllow,
	}, nil
}

func deniedByPolicy(policy compiledIPAccessPolicy, ipText string, clientASN uint32) bool {
	ip := net.ParseIP(ipText)
	if ip == nil {
		return policy.anyAllow
	}

	for _, source := range policy.sources {
		if source.allowFirst {
			if (len(source.allow) > 0 && matchAnyRule(source.allow, ip)) || matchAnyASNRule(source.allowASNs, clientASN) {
				return false
			}
			if (len(source.deny) > 0 && matchAnyRule(source.deny, ip)) || matchAnyASNRule(source.denyASNs, clientASN) || (len(source.denyReputation) > 0 && matchAnyRule(source.denyReputation, ip)) {
				return true
			}
			continue
		}
		if (len(source.deny) > 0 && matchAnyRule(source.deny, ip)) || matchAnyASNRule(source.denyASNs, clientASN) || (len(source.denyReputation) > 0 && matchAnyRule(source.denyReputation, ip)) {
			return true
		}
		if (len(source.allow) > 0 && matchAnyRule(source.allow, ip)) || matchAnyASNRule(source.allowASNs, clientASN) {
			return false
		}
	}
	if policy.anyAllow {
		return true
	}
	return false
}

func matchAnyASNRule(rules map[uint32]struct{}, asn uint32) bool {
	if len(rules) == 0 || asn == 0 {
		return false
	}
	_, ok := rules[asn]
	return ok
}

func parseASNRules(raw []string) (map[uint32]struct{}, error) {
	out := map[uint32]struct{}{}
	for _, item := range raw {
		asn, ok, err := parseASNText(item)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out[asn] = struct{}{}
	}
	return out, nil
}

func clientASNFromRequest(req *http.Request) uint32 {
	for _, key := range []string{"X-Client-ASN", "X-ASN", "CF-ASN", "True-Client-ASN"} {
		value := strings.TrimSpace(req.Header.Get(key))
		asn, ok, err := parseASNText(value)
		if err == nil && ok {
			return asn
		}
	}
	return 0
}

func parseASNText(raw string) (uint32, bool, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, false, nil
	}
	first := value
	if idx := strings.IndexAny(value, ",; "); idx >= 0 {
		first = value[:idx]
	}
	first = strings.ToUpper(strings.TrimSpace(first))
	first = strings.TrimPrefix(first, "AS")
	if first == "" {
		return 0, false, nil
	}
	parsed, err := strconv.ParseUint(first, 10, 32)
	if err != nil || parsed == 0 {
		return 0, false, fmt.Errorf("invalid asn: %s", raw)
	}
	return uint32(parsed), true, nil
}

func matchAnyRule(rules []ipRule, ip net.IP) bool {
	for _, rule := range rules {
		if rule.net != nil && rule.net.Contains(ip) {
			return true
		}
		if rule.ip != nil && rule.ip.Equal(ip) {
			return true
		}
	}
	return false
}

func normalizeRuntimeConflictPolicy(input string) string {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case settings.IPRuleConflictAllowFirst, "allow-first", "allowfirst":
		return settings.IPRuleConflictAllowFirst
	case settings.IPRuleConflictDenyFirst, "deny-first", "denyfirst":
		return settings.IPRuleConflictDenyFirst
	default:
		return settings.IPRuleConflictAllowFirst
	}
}

func (l *rateLimiter) allow(clientIP string) rateLimitDecision {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	state, ok := l.byIP[clientIP]
	if !ok {
		state = &bucketState{
			tokens: l.burst,
			last:   now,
		}
		l.byIP[clientIP] = state
	}

	if l.autoBlock.enabled && !state.blockedUntil.IsZero() {
		if now.Before(state.blockedUntil) {
			return rateLimitDecision{
				allowed:    false,
				blocked:    true,
				retryAfter: state.blockedUntil.Sub(now),
			}
		}
		state.blockedUntil = time.Time{}
		state.violationCount = 0
		state.violationWindowStart = time.Time{}
	}

	elapsed := now.Sub(state.last).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	state.last = now
	state.tokens = math.Min(l.burst, state.tokens+elapsed*l.ratePerSec)
	if state.tokens < 1 {
		if l.autoBlock.enabled {
			l.registerViolation(state, now)
			if !state.blockedUntil.IsZero() && now.Before(state.blockedUntil) {
				return rateLimitDecision{
					allowed:    false,
					blocked:    true,
					retryAfter: state.blockedUntil.Sub(now),
				}
			}
		}
		return rateLimitDecision{allowed: false}
	}
	state.tokens--
	if l.autoBlock.enabled && !state.violationWindowStart.IsZero() && now.Sub(state.violationWindowStart) > l.autoBlock.violationWindow {
		state.violationCount = 0
		state.violationWindowStart = time.Time{}
	}
	return rateLimitDecision{allowed: true}
}

func (l *rateLimiter) registerViolation(state *bucketState, now time.Time) {
	if state.violationWindowStart.IsZero() || now.Sub(state.violationWindowStart) > l.autoBlock.violationWindow {
		state.violationWindowStart = now
		state.violationCount = 0
	}
	state.violationCount++
	if state.violationCount < l.autoBlock.violationThreshold {
		return
	}
	state.blockedUntil = now.Add(l.autoBlock.blockDuration)
	state.violationCount = 0
	state.violationWindowStart = time.Time{}
}

func resolveAutoBlockPolicy(cfg site.AutoBlockConfig) autoBlockPolicy {
	if !cfg.Enabled {
		return autoBlockPolicy{}
	}

	threshold := cfg.ViolationThreshold
	if threshold <= 0 {
		threshold = defaultAutoBlockThreshold
	}
	window := time.Duration(cfg.ViolationWindowSeconds) * time.Second
	if window <= 0 {
		window = defaultAutoBlockWindow
	}
	blockDuration := time.Duration(cfg.BlockSeconds) * time.Second
	if blockDuration <= 0 {
		blockDuration = defaultAutoBlockDuration
	}

	return autoBlockPolicy{
		enabled:            true,
		violationThreshold: threshold,
		violationWindow:    window,
		blockDuration:      blockDuration,
	}
}

func resolveActiveHealthPolicy(cfg site.ActiveHealthCheckConfig) activeHealthPolicy {
	if !cfg.Enabled {
		return activeHealthPolicy{}
	}
	interval := time.Duration(cfg.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	path := strings.TrimSpace(cfg.Path)
	if path == "" {
		path = "/health"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return activeHealthPolicy{
		enabled:        true,
		interval:       interval,
		timeout:        timeout,
		path:           path,
		expectedStatus: cfg.ExpectedStatus,
	}
}

func resolveRetryPolicy(cfg site.RetryConfig) retryPolicy {
	if !cfg.Enabled {
		return retryPolicy{}
	}
	attempts := cfg.Attempts
	if attempts <= 0 {
		attempts = 2
	}
	statuses := map[int]struct{}{}
	statusList := site.NormalizeStatusCodes(cfg.RetryOnStatuses)
	if cfg.RetryOnStatuses == nil && len(statusList) == 0 {
		statusList = []int{502, 503, 504}
	}
	for _, code := range statusList {
		statuses[code] = struct{}{}
	}
	backoffStrategy := strings.ToLower(strings.TrimSpace(cfg.BackoffStrategy))
	if backoffStrategy == "" {
		backoffStrategy = site.RetryBackoffFixed
	}
	backoff := durationFromMillis(cfg.BackoffMillis)
	maxBackoff := durationFromMillis(cfg.MaxBackoffMillis)
	if maxBackoff <= 0 {
		maxBackoff = 5 * time.Second
	}
	jitterPercent := cfg.JitterPercent
	if jitterPercent < 0 {
		jitterPercent = 0
	}
	if jitterPercent > 100 {
		jitterPercent = 100
	}
	retryOn5xx := cfg.RetryOn5xx
	retryOnTimeout := cfg.RetryOnTimeout
	retryOnConnection := cfg.RetryOnConnection
	if !retryOn5xx && !retryOnTimeout && !retryOnConnection {
		retryOn5xx = true
	}
	return retryPolicy{
		enabled:           true,
		attempts:          attempts,
		statuses:          statuses,
		statusList:        statusList,
		backoff:           backoff,
		maxBackoff:        maxBackoff,
		jitterPercent:     jitterPercent,
		backoffStrategy:   backoffStrategy,
		retryOn5xx:        retryOn5xx,
		retryOnTimeout:    retryOnTimeout,
		retryOnConnection: retryOnConnection,
	}
}

func resolveCircuitBreakerPolicy(cfg site.CircuitBreakerConfig) circuitBreakerPolicy {
	if !cfg.Enabled {
		return circuitBreakerPolicy{}
	}
	threshold := cfg.FailureThreshold
	if threshold <= 0 {
		threshold = 5
	}
	openDuration := time.Duration(cfg.OpenSeconds) * time.Second
	if openDuration <= 0 {
		openDuration = 30 * time.Second
	}
	return circuitBreakerPolicy{
		enabled:          true,
		failureThreshold: int64(threshold),
		openDuration:     openDuration,
	}
}

func (p retryPolicy) effectiveAttempts(req *http.Request) int {
	if !p.enabled || p.attempts <= 1 {
		return 1
	}
	if req == nil {
		return 1
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		return 1
	}
	if req.GetBody == nil && req.Body != nil && req.Body != http.NoBody {
		return 1
	}
	if isUpgradeRequest(req.Header) {
		return 1
	}
	return p.attempts
}

func (p retryPolicy) shouldRetry(statusCode int) bool {
	if !p.enabled {
		return false
	}
	if len(p.statuses) > 0 {
		_, ok := p.statuses[statusCode]
		return ok
	}
	if p.retryOnTimeout && statusCode == http.StatusGatewayTimeout {
		return true
	}
	if p.retryOnConnection && statusCode == http.StatusBadGateway {
		return true
	}
	if p.retryOn5xx && statusCode >= 500 {
		return true
	}
	return false
}

func (p retryPolicy) backoffDelay(attempt int) time.Duration {
	if !p.enabled || attempt < 0 || p.backoff <= 0 {
		return 0
	}
	delay := p.backoff
	if p.backoffStrategy == site.RetryBackoffExponential {
		multiplier := 1 << attempt
		delay = time.Duration(multiplier) * p.backoff
	}
	if p.maxBackoff > 0 && delay > p.maxBackoff {
		delay = p.maxBackoff
	}
	if p.jitterPercent <= 0 {
		return delay
	}
	rangeMs := delay.Milliseconds() * int64(p.jitterPercent) / 100
	if rangeMs <= 0 {
		return delay
	}
	shift := mathrand.Int63n(rangeMs*2+1) - rangeMs
	jittered := delay + time.Duration(shift)*time.Millisecond
	if jittered < 0 {
		return 0
	}
	return jittered
}

func (r *canaryRule) match(req *http.Request, clientIP string) bool {
	if r == nil || req == nil {
		return false
	}
	matchedBySelector := false
	if r.header != "" {
		value := strings.TrimSpace(req.Header.Get(r.header))
		if value == "" {
			return false
		}
		if r.headerValue != "" && value != r.headerValue {
			return false
		}
		matchedBySelector = true
	}
	if r.cookie != "" {
		cookie, err := req.Cookie(r.cookie)
		if err != nil || strings.TrimSpace(cookie.Value) == "" {
			return false
		}
		if r.cookieValue != "" && cookie.Value != r.cookieValue {
			return false
		}
		matchedBySelector = true
	}
	if matchedBySelector {
		return true
	}
	if r.weight <= 0 {
		return false
	}
	key := clientIP + "|" + req.URL.Path
	return int(hashText(key)%100) < r.weight
}

func cloneHeaders(in []site.Header) []site.Header {
	out := make([]site.Header, 0, len(in))
	for _, header := range in {
		name := http.CanonicalHeaderKey(strings.TrimSpace(header.Name))
		if name == "" {
			continue
		}
		out = append(out, site.Header{
			Name:  name,
			Value: strings.TrimSpace(header.Value),
		})
	}
	return out
}

func methodSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		value := strings.ToUpper(strings.TrimSpace(item))
		if value == "" {
			continue
		}
		out[value] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func canonicalHeaderList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		name := http.CanonicalHeaderKey(strings.TrimSpace(item))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func setHeaderIfAbsent(headers http.Header, key string, value string) {
	if headers.Get(key) != "" {
		return
	}
	headers.Set(key, value)
}

func setHeaderIfAllowed(headers http.Header, removed map[string]struct{}, key string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	if _, blocked := removed[key]; blocked {
		return
	}
	setHeaderIfAbsent(headers, key, value)
}

func setRequestHeaderIfAllowed(headers http.Header, removed map[string]struct{}, key string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	if _, blocked := removed[key]; blocked {
		return
	}
	headers.Set(key, value)
}

func setSecurityHeaderIfAllowed(headers http.Header, removed map[string]struct{}, key string, value string) {
	setHeaderIfAllowed(headers, removed, key, value)
}

func expandHeaderValue(template string, req *http.Request, clientIP string, requestID string, requestScheme string) string {
	out := strings.ReplaceAll(template, "$remote_addr", clientIP)
	out = strings.ReplaceAll(out, "$remote_port", "")
	out = strings.ReplaceAll(out, "$host", normalizeRequestHost(req.Host))
	out = strings.ReplaceAll(out, "$scheme", requestScheme)
	out = strings.ReplaceAll(out, "$request_id", requestID)
	return out
}

func normalizeRequestHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}
	return host
}

func forwardedPortValue(req *http.Request, requestScheme string, requestLocalPort int) string {
	if requestLocalPort > 0 {
		return strconv.Itoa(requestLocalPort)
	}
	host := strings.TrimSpace(req.Host)
	if _, port, err := net.SplitHostPort(host); err == nil && strings.TrimSpace(port) != "" {
		return strings.TrimSpace(port)
	}
	if requestScheme == "https" {
		return "443"
	}
	return "80"
}

func schemeFromRequest(req *http.Request, trustForwarded bool) string {
	if req.TLS != nil {
		return "https"
	}
	if trustForwarded {
		if xfp := normalizeForwardedProto(req.Header.Get("X-Forwarded-Proto")); xfp != "" {
			return xfp
		}
	}
	return "http"
}

func normalizeForwardedProto(raw string) string {
	parts := strings.Split(raw, ",")
	if len(parts) == 0 {
		return ""
	}
	value := strings.ToLower(strings.TrimSpace(parts[0]))
	switch value {
	case "http", "https":
		return value
	default:
		return ""
	}
}

func clientIPFromRequest(req *http.Request, trustForwarded bool, trustedProxyRules []ipRule) string {
	remoteIP := remoteIPFromAddr(req.RemoteAddr)
	if remoteIP == nil {
		return req.RemoteAddr
	}
	if trustForwarded {
		xff := parseForwardedForIPs(req.Header.Get("X-Forwarded-For"))
		if len(xff) > 0 {
			for i := len(xff) - 1; i >= 0; i-- {
				if !matchAnyRule(trustedProxyRules, xff[i]) {
					return xff[i].String()
				}
			}
			return xff[0].String()
		}
	}
	return remoteIP.String()
}

func isForwardedHeadersTrusted(req *http.Request, trustedProxyRules []ipRule) bool {
	if len(trustedProxyRules) == 0 {
		return false
	}
	remoteIP := remoteIPFromAddr(req.RemoteAddr)
	if remoteIP == nil {
		return false
	}
	return matchAnyRule(trustedProxyRules, remoteIP)
}

func remoteIPFromAddr(raw string) net.IP {
	host, _, err := net.SplitHostPort(raw)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(strings.TrimSpace(raw))
}

func parseForwardedForIPs(raw string) []net.IP {
	parts := strings.Split(raw, ",")
	out := make([]net.IP, 0, len(parts))
	for _, item := range parts {
		ip := net.ParseIP(strings.TrimSpace(item))
		if ip == nil {
			continue
		}
		out = append(out, ip)
	}
	return out
}

func localPortFromRequest(req *http.Request) int {
	addr, _ := req.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if addr == nil {
		return 0
	}
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return value
}

func hashText(text string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(text))
	return h.Sum64()
}

func newRequestID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
	mutate func(http.Header)
}

func (w *statusRecorder) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *statusRecorder) WriteHeader(statusCode int) {
	if !w.wrote {
		w.wrote = true
		w.status = statusCode
		if w.mutate != nil {
			w.mutate(w.ResponseWriter.Header())
		}
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *statusRecorder) Write(data []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (w *statusRecorder) Flush() {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusRecorder) ReadFrom(reader io.Reader) (int64, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(reader)
	}
	return io.Copy(w.ResponseWriter, reader)
}

func (w *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	return hj.Hijack()
}

func (w *statusRecorder) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *statusRecorder) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *statusRecorder) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func durationFromMillis(ms int) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

func roundFloat(v float64, precision int) float64 {
	m := math.Pow10(precision)
	return math.Round(v*m) / m
}

func errorsf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
