package site

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Site struct {
	ID                    string               `json:"id"`
	Name                  string               `json:"name,omitempty"`
	NodeID                string               `json:"nodeId,omitempty"`
	Protocol              string               `json:"protocol,omitempty"`
	BindInterfaces        []string             `json:"bindInterfaces,omitempty"`
	Domain                string               `json:"domain"`
	ListenPort            int                  `json:"listenPort,omitempty"`
	AdditionalDomains     []string             `json:"additionalDomains,omitempty"`
	CertificateID         string               `json:"certificateId,omitempty"`
	Upstream              string               `json:"upstream,omitempty"`
	Upstreams             []Upstream           `json:"upstreams,omitempty"`
	UpstreamTLS           UpstreamTLSConfig    `json:"upstreamTls,omitempty"`
	LoadBalanceStrategy   string               `json:"loadBalanceStrategy,omitempty"`
	Routes                []RouteRule          `json:"routes,omitempty"`
	Resilience            ResilienceConfig     `json:"resilience,omitempty"`
	Timeouts              TimeoutConfig        `json:"timeouts,omitempty"`
	Cache                 CacheConfig          `json:"cache,omitempty"`
	Gzip                  GzipConfig           `json:"gzip,omitempty"`
	Brotli                BrotliConfig         `json:"brotli,omitempty"`
	Canary                CanaryConfig         `json:"canary,omitempty"`
	AutoRequestHeaders    bool                 `json:"autoRequestHeaders,omitempty"`
	AutoResponseHeaders   bool                 `json:"autoResponseHeaders,omitempty"`
	RequestHeaders        []Header             `json:"requestHeaders,omitempty"`
	ResponseHeaders       []Header             `json:"responseHeaders,omitempty"`
	RemoveRequestHeaders  []string             `json:"removeRequestHeaders,omitempty"`
	RemoveResponseHeaders []string             `json:"removeResponseHeaders,omitempty"`
	RateLimit             RateLimitConfig      `json:"rateLimit,omitempty"`
	TrafficControl        TrafficControlConfig `json:"trafficControl,omitempty"`
	IPRuleSetIDs          []string             `json:"ipRuleSetIds,omitempty"`
	IPRuleSetID           string               `json:"ipRuleSetId,omitempty"`
	IPAccess              IPAccessConfig       `json:"ipAccess,omitempty"`
	IPAccessPolicy        IPAccessPolicy       `json:"-"`
	BasicAuth             BasicAuthConfig      `json:"basicAuth,omitempty"`
	Security              SecurityConfig       `json:"security,omitempty"`
	JWT                   JWTConfig            `json:"jwt,omitempty"`
	GRPC                  GRPCConfig           `json:"grpc,omitempty"`
	WAF                   WAFConfig            `json:"waf,omitempty"`
	OAuth                 OAuthConfig          `json:"oauth,omitempty"`
	Enabled               bool                 `json:"enabled"`
	ForceHTTPS            bool                 `json:"forceHttps"`
	CreatedAt             time.Time            `json:"createdAt"`
	UpdatedAt             time.Time            `json:"updatedAt"`
}

type Upstream struct {
	URL    string `json:"url"`
	Weight int    `json:"weight,omitempty"`
}

type RouteRule struct {
	Path                string     `json:"path"`
	Match               string     `json:"match,omitempty"`
	Methods             []string   `json:"methods,omitempty"`
	Header              string     `json:"header,omitempty"`
	HeaderValue         string     `json:"headerValue,omitempty"`
	Cookie              string     `json:"cookie,omitempty"`
	CookieValue         string     `json:"cookieValue,omitempty"`
	Query               string     `json:"query,omitempty"`
	QueryValue          string     `json:"queryValue,omitempty"`
	Upstream            string     `json:"upstream,omitempty"`
	Upstreams           []Upstream `json:"upstreams,omitempty"`
	LoadBalanceStrategy string     `json:"loadBalanceStrategy,omitempty"`
	Priority            int        `json:"priority,omitempty"`
	RewritePattern      string     `json:"rewritePattern,omitempty"`
	RewriteReplacement  string     `json:"rewriteReplacement,omitempty"`
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type UpstreamTLSConfig struct {
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
	ServerName         string `json:"serverName,omitempty"`
	RootCAFile         string `json:"rootCAFile,omitempty"`
	RootCAPEM          string `json:"rootCAPem,omitempty"`
}

type ResilienceConfig struct {
	ActiveHealthCheck ActiveHealthCheckConfig `json:"activeHealthCheck,omitempty"`
	Retry             RetryConfig             `json:"retry,omitempty"`
	CircuitBreaker    CircuitBreakerConfig    `json:"circuitBreaker,omitempty"`
}

type ActiveHealthCheckConfig struct {
	Enabled         bool   `json:"enabled,omitempty"`
	IntervalSeconds int    `json:"intervalSeconds,omitempty"`
	TimeoutSeconds  int    `json:"timeoutSeconds,omitempty"`
	Path            string `json:"path,omitempty"`
	ExpectedStatus  int    `json:"expectedStatus,omitempty"`
}

type RetryConfig struct {
	Enabled           bool   `json:"enabled,omitempty"`
	Attempts          int    `json:"attempts,omitempty"`
	RetryOnStatuses   []int  `json:"retryOnStatuses,omitempty"`
	BackoffStrategy   string `json:"backoffStrategy,omitempty"`
	BackoffMillis     int    `json:"backoffMillis,omitempty"`
	MaxBackoffMillis  int    `json:"maxBackoffMillis,omitempty"`
	JitterPercent     int    `json:"jitterPercent,omitempty"`
	RetryOn5xx        bool   `json:"retryOn5xx,omitempty"`
	RetryOnTimeout    bool   `json:"retryOnTimeout,omitempty"`
	RetryOnConnection bool   `json:"retryOnConnection,omitempty"`
}

type CircuitBreakerConfig struct {
	Enabled          bool `json:"enabled,omitempty"`
	FailureThreshold int  `json:"failureThreshold,omitempty"`
	OpenSeconds      int  `json:"openSeconds,omitempty"`
}

type CanaryConfig struct {
	Enabled             bool       `json:"enabled,omitempty"`
	Header              string     `json:"header,omitempty"`
	HeaderValue         string     `json:"headerValue,omitempty"`
	Cookie              string     `json:"cookie,omitempty"`
	CookieValue         string     `json:"cookieValue,omitempty"`
	Weight              int        `json:"weight,omitempty"`
	Upstream            string     `json:"upstream,omitempty"`
	Upstreams           []Upstream `json:"upstreams,omitempty"`
	LoadBalanceStrategy string     `json:"loadBalanceStrategy,omitempty"`
}

type RateLimitConfig struct {
	Enabled           bool            `json:"enabled,omitempty"`
	RequestsPerMinute int             `json:"requestsPerMinute,omitempty"`
	Burst             int             `json:"burst,omitempty"`
	AutoBlock         AutoBlockConfig `json:"autoBlock,omitempty"`
}

type AutoBlockConfig struct {
	Enabled                bool `json:"enabled,omitempty"`
	ViolationThreshold     int  `json:"violationThreshold,omitempty"`
	ViolationWindowSeconds int  `json:"violationWindowSeconds,omitempty"`
	BlockSeconds           int  `json:"blockSeconds,omitempty"`
}

type TrafficControlConfig struct {
	MaxConcurrentRequests int      `json:"maxConcurrentRequests,omitempty"`
	MaxConcurrentPerIP    int      `json:"maxConcurrentPerIp,omitempty"`
	AllowedMethods        []string `json:"allowedMethods,omitempty"`
}

type CacheConfig struct {
	Enabled              bool     `json:"enabled,omitempty"`
	TTLSeconds           int      `json:"ttlSeconds,omitempty"`
	MaxEntries           int      `json:"maxEntries,omitempty"`
	MaxBodyBytes         int      `json:"maxBodyBytes,omitempty"`
	Proactive            bool     `json:"proactive,omitempty"`
	KeyIgnoreQueryParams []string `json:"keyIgnoreQueryParams,omitempty"`
}

type TimeoutConfig struct {
	ConnectMillis            int  `json:"connectMillis,omitempty"`
	ResponseHeaderMillis     int  `json:"responseHeaderMillis,omitempty"`
	ExpectContinueMillis     int  `json:"expectContinueMillis,omitempty"`
	IdleConnMillis           int  `json:"idleConnMillis,omitempty"`
	RequestMillis            int  `json:"requestMillis,omitempty"`
	BackendKeepaliveMillis   int  `json:"backendKeepaliveMillis,omitempty"`
	TLSHandshakeMillis       int  `json:"tlsHandshakeMillis,omitempty"`
	MaxIdleConnsPerHost      int  `json:"maxIdleConnsPerHost,omitempty"`
	MaxBackendConnections    int  `json:"maxBackendConnections,omitempty"`
	BackendKeepaliveDisabled bool `json:"backendKeepaliveDisabled,omitempty"`
}

type GzipConfig struct {
	Enabled bool `json:"enabled,omitempty"`
}

type BrotliConfig struct {
	Enabled bool `json:"enabled,omitempty"`
}

type IPAccessConfig struct {
	AllowCIDRs          []string `json:"allowCidrs,omitempty"`
	DenyCIDRs           []string `json:"denyCidrs,omitempty"`
	AllowASNs           []string `json:"allowAsns,omitempty"`
	DenyASNs            []string `json:"denyAsns,omitempty"`
	DenyReputationCIDRs []string `json:"denyReputationCidrs,omitempty"`
}

type IPAccessSourceRules struct {
	Source              string
	ConflictPolicy      string
	AllowCIDRs          []string
	DenyCIDRs           []string
	AllowASNs           []string
	DenyASNs            []string
	DenyReputationCIDRs []string
}

type IPAccessPolicy struct {
	SourceOrder []string
	Sources     []IPAccessSourceRules
}

type BasicAuthConfig struct {
	Enabled      bool   `json:"enabled,omitempty"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	PasswordHash string `json:"passwordHash,omitempty"`
}

type SecurityConfig struct {
	EnableSecurityHeaders  bool     `json:"enableSecurityHeaders,omitempty"`
	BlockUserAgentPatterns []string `json:"blockUserAgentPatterns,omitempty"`
}

// JWTConfig defines JWT authentication configuration for a site.
type JWTConfig struct {
	Enabled          bool   `json:"enabled,omitempty"`
	ExtractFrom      string `json:"extractFrom,omitempty"`
	ExtractName      string `json:"extractName,omitempty"`
	SigningAlgorithm string `json:"signingAlgorithm,omitempty"`
	HMACSecret       string `json:"hmacSecret,omitempty"`
	JWKSURL          string `json:"jwksUrl,omitempty"`
	JWKSRefreshSec   int    `json:"jwksRefreshSec,omitempty"`
	Issuer           string `json:"issuer,omitempty"`
	Audience         string `json:"audience,omitempty"`
	ForwardToken     bool   `json:"forwardToken,omitempty"`
}

// GRPCConfig defines gRPC proxy configuration for a site.
type GRPCConfig struct {
	Enabled bool `json:"enabled,omitempty"`
	// H2C enables cleartext HTTP/2 for gRPC without TLS.
	H2C bool `json:"h2c,omitempty"`
	// GRPCWeb enables gRPC-Web compatibility.
	GRPCWeb bool `json:"grpcWeb,omitempty"`
}

// WAFConfig defines Web Application Firewall configuration for a site.
type WAFConfig struct {
	Enabled           bool     `json:"enabled,omitempty"`
	Mode              string   `json:"mode,omitempty"`
	SeverityThreshold string   `json:"severityThreshold,omitempty"`
	ExcludePaths      []string `json:"excludePaths,omitempty"`
}

// OAuthConfig defines OAuth/OIDC authentication configuration for a site.
type OAuthConfig struct {
	Enabled        bool     `json:"enabled,omitempty"`
	Provider       string   `json:"provider,omitempty"`
	ClientID       string   `json:"clientId,omitempty"`
	ClientSecret   string   `json:"clientSecret,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	AllowedDomains []string `json:"allowedDomains,omitempty"`
	AllowedEmails  []string `json:"allowedEmails,omitempty"`
	CallbackURL    string   `json:"callbackUrl,omitempty"`
}

const (
	MatchPrefix             = "prefix"
	MatchExact              = "exact"
	MatchRegex              = "regex"
	LoadBalanceRound        = "round_robin"
	LoadBalanceWeight       = "weighted_round_robin"
	LoadBalanceRandom       = "random"
	LoadBalanceIPHash       = "ip_hash"
	LoadBalanceLeast        = "least_conn"
	RetryBackoffFixed       = "fixed"
	RetryBackoffExponential = "exponential"
)

var hostLabelRegexp = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
var httpMethodRegexp = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)

func NormalizeHost(rawHost string) string {
	host := strings.ToLower(strings.TrimSpace(rawHost))
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}
	return host
}

func NormalizeDomainPattern(raw string) string {
	return NormalizeHost(raw)
}

func NormalizeDomains(primary string, extras []string) (string, []string) {
	primary = NormalizeDomainPattern(primary)
	normalizedExtras := make([]string, 0, len(extras))
	seen := map[string]struct{}{}
	if primary != "" {
		seen[primary] = struct{}{}
	}
	for _, domain := range extras {
		d := NormalizeDomainPattern(domain)
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		normalizedExtras = append(normalizedExtras, d)
	}
	slices.Sort(normalizedExtras)
	return primary, normalizedExtras
}

func AllDomains(item Site) []string {
	domain, extras := NormalizeDomains(item.Domain, item.AdditionalDomains)
	out := make([]string, 0, 1+len(extras))
	if domain != "" {
		out = append(out, domain)
	}
	out = append(out, extras...)
	return out
}

func NormalizeUpstreams(upstream string, upstreams []Upstream) (string, []Upstream) {
	upstream = strings.TrimSpace(upstream)
	normalized := make([]Upstream, 0, len(upstreams))
	for _, up := range upstreams {
		urlValue := strings.TrimSpace(up.URL)
		if urlValue == "" {
			continue
		}
		weight := up.Weight
		if weight <= 0 {
			weight = 1
		}
		normalized = append(normalized, Upstream{
			URL:    urlValue,
			Weight: weight,
		})
	}
	return upstream, normalized
}

func NormalizeHTTPMethods(methods []string) []string {
	out := make([]string, 0, len(methods))
	seen := map[string]struct{}{}
	for _, method := range methods {
		value := strings.ToUpper(strings.TrimSpace(method))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func NormalizeStatusCodes(items []int) []int {
	out := make([]int, 0, len(items))
	seen := map[int]struct{}{}
	for _, code := range items {
		if code <= 0 {
			continue
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		out = append(out, code)
	}
	slices.Sort(out)
	return out
}

func NormalizeQueryKeys(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		value := strings.ToLower(strings.TrimSpace(item))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func Validate(input Site) error {
	input.NodeID = strings.TrimSpace(input.NodeID)
	input.CertificateID = strings.TrimSpace(input.CertificateID)
	input.Protocol = strings.ToLower(strings.TrimSpace(input.Protocol))
	isL4 := false
	switch input.Protocol {
	case "tcp", "udp", "tls":
		isL4 = true
	case "":
		// Default: HTTP mode
		input.Protocol = ""
	default:
		return fmt.Errorf("invalid protocol: %s (supported: tcp, udp, tls, or empty for HTTP)", input.Protocol)
	}

	input.Domain, input.AdditionalDomains = NormalizeDomains(input.Domain, input.AdditionalDomains)
	if input.ListenPort < 0 || input.ListenPort > 65535 {
		return errors.New("listenPort must be within 1-65535 when set")
	}

	if isL4 {
		// L4 port forwarding validation
		if input.ListenPort == 0 {
			return errors.New("listenPort is required for tcp/udp/tls protocol")
		}
	} else {
		if input.Domain == "" && input.ListenPort == 0 {
			return errors.New("domain or listenPort is required")
		}
		if input.Domain != "" || len(input.AdditionalDomains) > 0 {
			domains := AllDomains(input)
			for _, domain := range domains {
				if !isValidDomainPattern(domain) {
					return fmt.Errorf("invalid domain pattern: %s", domain)
				}
			}
		}
	}

	input.Upstream, input.Upstreams = NormalizeUpstreams(input.Upstream, input.Upstreams)
	if input.Upstream == "" && len(input.Upstreams) == 0 {
		return errors.New("at least one upstream is required")
	}

	if isL4 {
		if err := validateL4Upstream(input.Upstream, input.Upstreams); err != nil {
			return err
		}
		return nil
	}

	if input.Upstream != "" {
		if err := validateUpstreamURL(input.Upstream); err != nil {
			return err
		}
	}
	for _, up := range input.Upstreams {
		if err := validateUpstreamURL(up.URL); err != nil {
			return err
		}
		if up.Weight <= 0 {
			return errors.New("upstream weight must be greater than 0")
		}
	}

	if input.LoadBalanceStrategy == "" {
		input.LoadBalanceStrategy = LoadBalanceRound
	}
	if !isValidLoadBalance(input.LoadBalanceStrategy) {
		return fmt.Errorf("invalid load balance strategy: %s", input.LoadBalanceStrategy)
	}
	if err := validateUpstreamTLS(input.UpstreamTLS); err != nil {
		return err
	}

	for i, route := range input.Routes {
		if err := validateRoute(route, i); err != nil {
			return err
		}
	}

	if err := validateHeaders(input.RequestHeaders, "request"); err != nil {
		return err
	}
	if err := validateHeaders(input.ResponseHeaders, "response"); err != nil {
		return err
	}
	if err := validateHeaderNames(input.RemoveRequestHeaders, "remove request"); err != nil {
		return err
	}
	if err := validateHeaderNames(input.RemoveResponseHeaders, "remove response"); err != nil {
		return err
	}

	if input.RateLimit.Enabled {
		if input.RateLimit.RequestsPerMinute <= 0 {
			return errors.New("rate limit requestsPerMinute must be greater than 0")
		}
		if input.RateLimit.Burst < 0 {
			return errors.New("rate limit burst cannot be negative")
		}
	}
	if input.RateLimit.AutoBlock.Enabled && !input.RateLimit.Enabled {
		return errors.New("rate limit autoBlock requires rate limit enabled")
	}
	if input.RateLimit.AutoBlock.ViolationThreshold < 0 {
		return errors.New("rate limit autoBlock violationThreshold cannot be negative")
	}
	if input.RateLimit.AutoBlock.ViolationWindowSeconds < 0 {
		return errors.New("rate limit autoBlock violationWindowSeconds cannot be negative")
	}
	if input.RateLimit.AutoBlock.BlockSeconds < 0 {
		return errors.New("rate limit autoBlock blockSeconds cannot be negative")
	}
	if input.TrafficControl.MaxConcurrentRequests < 0 {
		return errors.New("traffic control maxConcurrentRequests cannot be negative")
	}
	if err := validateHTTPMethods(input.TrafficControl.AllowedMethods); err != nil {
		return err
	}

	if err := validateCIDRs(input.IPAccess.AllowCIDRs, "allow"); err != nil {
		return err
	}
	if err := validateCIDRs(input.IPAccess.DenyCIDRs, "deny"); err != nil {
		return err
	}
	if err := validateASNs(input.IPAccess.AllowASNs, "allow"); err != nil {
		return err
	}
	if err := validateASNs(input.IPAccess.DenyASNs, "deny"); err != nil {
		return err
	}
	if err := validateCIDRs(input.IPAccess.DenyReputationCIDRs, "denyReputation"); err != nil {
		return err
	}

	if input.BasicAuth.Enabled {
		if strings.TrimSpace(input.BasicAuth.Username) == "" {
			return errors.New("basic auth username is required")
		}
		if strings.TrimSpace(input.BasicAuth.PasswordHash) == "" && strings.TrimSpace(input.BasicAuth.Password) == "" {
			return errors.New("basic auth password is required")
		}
	}
	if err := validateRegexList(input.Security.BlockUserAgentPatterns, "security blockUserAgentPatterns"); err != nil {
		return err
	}
	if err := validateResilience(input.Resilience); err != nil {
		return err
	}
	if err := validateTimeouts(input.Timeouts); err != nil {
		return err
	}
	if err := validateCanary(input.Canary); err != nil {
		return err
	}
	if err := validateCache(input.Cache); err != nil {
		return err
	}
	return nil
}

func validateUpstreamTLS(cfg UpstreamTLSConfig) error {
	cfg.ServerName = strings.TrimSpace(cfg.ServerName)
	cfg.RootCAFile = strings.TrimSpace(cfg.RootCAFile)
	cfg.RootCAPEM = strings.TrimSpace(cfg.RootCAPEM)
	if cfg.ServerName == "" && cfg.RootCAFile == "" && cfg.RootCAPEM == "" && !cfg.InsecureSkipVerify {
		return nil
	}
	if cfg.ServerName != "" {
		if strings.ContainsAny(cfg.ServerName, " /") {
			return errors.New("upstream tls serverName is invalid")
		}
	}
	return nil
}

func validateResilience(cfg ResilienceConfig) error {
	hc := cfg.ActiveHealthCheck
	if hc.IntervalSeconds < 0 {
		return errors.New("active health check intervalSeconds cannot be negative")
	}
	if hc.TimeoutSeconds < 0 {
		return errors.New("active health check timeoutSeconds cannot be negative")
	}
	if hc.ExpectedStatus < 0 || hc.ExpectedStatus > 999 {
		return errors.New("active health check expectedStatus must be within 0-999")
	}
	if hc.Enabled {
		if hc.IntervalSeconds <= 0 {
			return errors.New("active health check intervalSeconds must be greater than 0")
		}
		if hc.TimeoutSeconds <= 0 {
			return errors.New("active health check timeoutSeconds must be greater than 0")
		}
	}
	retry := cfg.Retry
	retry.BackoffStrategy = strings.ToLower(strings.TrimSpace(retry.BackoffStrategy))
	if retry.Attempts < 0 {
		return errors.New("retry attempts cannot be negative")
	}
	for _, code := range retry.RetryOnStatuses {
		if code < 100 || code > 599 {
			return fmt.Errorf("retry status code must be within 100-599: %d", code)
		}
	}
	if retry.Enabled && retry.Attempts <= 0 {
		return errors.New("retry attempts must be greater than 0 when retry is enabled")
	}
	if retry.BackoffMillis < 0 {
		return errors.New("retry backoffMillis cannot be negative")
	}
	if retry.MaxBackoffMillis < 0 {
		return errors.New("retry maxBackoffMillis cannot be negative")
	}
	if retry.JitterPercent < 0 || retry.JitterPercent > 100 {
		return errors.New("retry jitterPercent must be within 0-100")
	}
	if retry.BackoffStrategy != "" && retry.BackoffStrategy != RetryBackoffFixed && retry.BackoffStrategy != RetryBackoffExponential {
		return errors.New("retry backoffStrategy must be fixed or exponential")
	}
	cb := cfg.CircuitBreaker
	if cb.FailureThreshold < 0 {
		return errors.New("circuit breaker failureThreshold cannot be negative")
	}
	if cb.OpenSeconds < 0 {
		return errors.New("circuit breaker openSeconds cannot be negative")
	}
	if cb.Enabled {
		if cb.FailureThreshold <= 0 {
			return errors.New("circuit breaker failureThreshold must be greater than 0")
		}
		if cb.OpenSeconds <= 0 {
			return errors.New("circuit breaker openSeconds must be greater than 0")
		}
	}
	return nil
}

func validateCanary(cfg CanaryConfig) error {
	cfg.Header = strings.TrimSpace(cfg.Header)
	cfg.HeaderValue = strings.TrimSpace(cfg.HeaderValue)
	cfg.Cookie = strings.TrimSpace(cfg.Cookie)
	cfg.CookieValue = strings.TrimSpace(cfg.CookieValue)
	cfg.Upstream, cfg.Upstreams = NormalizeUpstreams(cfg.Upstream, cfg.Upstreams)
	if !cfg.Enabled {
		return nil
	}
	if cfg.Weight < 0 || cfg.Weight > 100 {
		return errors.New("canary weight must be within 0-100")
	}
	if cfg.Upstream == "" && len(cfg.Upstreams) == 0 {
		return errors.New("canary requires at least one upstream")
	}
	if cfg.Upstream != "" {
		if err := validateUpstreamURL(cfg.Upstream); err != nil {
			return fmt.Errorf("canary upstream: %w", err)
		}
	}
	for _, up := range cfg.Upstreams {
		if err := validateUpstreamURL(up.URL); err != nil {
			return fmt.Errorf("canary upstreams: %w", err)
		}
		if up.Weight <= 0 {
			return errors.New("canary upstream weight must be greater than 0")
		}
	}
	if cfg.LoadBalanceStrategy == "" {
		cfg.LoadBalanceStrategy = LoadBalanceRound
	}
	if !isValidLoadBalance(cfg.LoadBalanceStrategy) {
		return fmt.Errorf("invalid canary load balance strategy: %s", cfg.LoadBalanceStrategy)
	}
	if cfg.Header == "" && cfg.Cookie == "" && cfg.Weight == 0 {
		return errors.New("canary requires header/cookie match or weight > 0")
	}
	return nil
}

func validateUpstreamURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return errors.New("invalid upstream URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("upstream must start with http:// or https://")
	}
	if u.Host == "" {
		return errors.New("upstream host is required")
	}
	return nil
}

func validateL4Upstream(upstream string, upstreams []Upstream) error {
	targets := make([]string, 0, 1+len(upstreams))
	if upstream != "" {
		targets = append(targets, upstream)
	}
	for _, up := range upstreams {
		targets = append(targets, up.URL)
	}
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if strings.Contains(target, "://") {
			u, err := url.Parse(target)
			if err != nil {
				return fmt.Errorf("invalid L4 upstream URL %q: %w", target, err)
			}
			if u.Host == "" {
				return fmt.Errorf("L4 upstream %q has no host", target)
			}
		} else {
			_, _, err := net.SplitHostPort(target)
			if err != nil {
				return fmt.Errorf("L4 upstream %q must be host:port or scheme://host:port format", target)
			}
		}
	}
	return nil
}

func validateRoute(route RouteRule, index int) error {
	match := strings.TrimSpace(route.Match)
	if match == "" {
		match = MatchPrefix
	}
	if match != MatchPrefix && match != MatchExact && match != MatchRegex {
		return fmt.Errorf("route[%d] has invalid match type", index)
	}
	if strings.TrimSpace(route.Path) == "" {
		return fmt.Errorf("route[%d] path is required", index)
	}
	if match != MatchRegex && !strings.HasPrefix(route.Path, "/") {
		return fmt.Errorf("route[%d] path must start with /", index)
	}
	if match == MatchRegex {
		if _, err := regexp.Compile(route.Path); err != nil {
			return fmt.Errorf("route[%d] invalid regex path: %w", index, err)
		}
	}
	if err := validateHTTPMethods(route.Methods); err != nil {
		return fmt.Errorf("route[%d]: %w", index, err)
	}
	if strings.TrimSpace(route.Header) != "" && !isValidHeaderName(route.Header) {
		return fmt.Errorf("route[%d] header has invalid name", index)
	}
	route.Cookie = strings.TrimSpace(route.Cookie)
	route.Query = strings.TrimSpace(route.Query)
	if route.Cookie == "" && strings.TrimSpace(route.CookieValue) != "" {
		return fmt.Errorf("route[%d] cookieValue requires cookie", index)
	}
	if route.Query == "" && strings.TrimSpace(route.QueryValue) != "" {
		return fmt.Errorf("route[%d] queryValue requires query", index)
	}
	route.Upstream, route.Upstreams = NormalizeUpstreams(route.Upstream, route.Upstreams)
	if route.Upstream == "" && len(route.Upstreams) == 0 {
		return fmt.Errorf("route[%d] requires upstream", index)
	}
	if route.Upstream != "" {
		if err := validateUpstreamURL(route.Upstream); err != nil {
			return fmt.Errorf("route[%d]: %w", index, err)
		}
	}
	for _, up := range route.Upstreams {
		if err := validateUpstreamURL(up.URL); err != nil {
			return fmt.Errorf("route[%d]: %w", index, err)
		}
		if up.Weight <= 0 {
			return fmt.Errorf("route[%d] upstream weight must be greater than 0", index)
		}
	}
	if route.LoadBalanceStrategy != "" && !isValidLoadBalance(route.LoadBalanceStrategy) {
		return fmt.Errorf("route[%d] invalid load balance strategy", index)
	}
	if route.RewritePattern != "" {
		if _, err := regexp.Compile(route.RewritePattern); err != nil {
			return fmt.Errorf("route[%d] invalid rewritePattern: %w", index, err)
		}
	}
	return nil
}

func validateTimeouts(cfg TimeoutConfig) error {
	if cfg.ConnectMillis < 0 {
		return errors.New("timeouts connectMillis cannot be negative")
	}
	if cfg.ResponseHeaderMillis < 0 {
		return errors.New("timeouts responseHeaderMillis cannot be negative")
	}
	if cfg.ExpectContinueMillis < 0 {
		return errors.New("timeouts expectContinueMillis cannot be negative")
	}
	if cfg.IdleConnMillis < 0 {
		return errors.New("timeouts idleConnMillis cannot be negative")
	}
	if cfg.RequestMillis < 0 {
		return errors.New("timeouts requestMillis cannot be negative")
	}
	if cfg.BackendKeepaliveMillis < 0 {
		return errors.New("timeouts backendKeepaliveMillis cannot be negative")
	}
	if cfg.TLSHandshakeMillis < 0 {
		return errors.New("timeouts tlsHandshakeMillis cannot be negative")
	}
	if cfg.MaxIdleConnsPerHost < 0 {
		return errors.New("timeouts maxIdleConnsPerHost cannot be negative")
	}
	if cfg.MaxBackendConnections < 0 {
		return errors.New("timeouts maxBackendConnections cannot be negative")
	}
	return nil
}

func validateCache(cfg CacheConfig) error {
	if cfg.TTLSeconds < 0 {
		return errors.New("cache ttlSeconds cannot be negative")
	}
	if cfg.MaxEntries < 0 {
		return errors.New("cache maxEntries cannot be negative")
	}
	if cfg.MaxBodyBytes < 0 {
		return errors.New("cache maxBodyBytes cannot be negative")
	}
	for i, key := range cfg.KeyIgnoreQueryParams {
		if strings.TrimSpace(key) == "" {
			continue
		}
		if strings.ContainsAny(key, " &=") {
			return fmt.Errorf("cache keyIgnoreQueryParams[%d] is invalid", i)
		}
	}
	return nil
}

func validateHeaders(headers []Header, scope string) error {
	for i, header := range headers {
		if strings.TrimSpace(header.Name) == "" {
			return fmt.Errorf("%s header[%d] name is required", scope, i)
		}
		if !isValidHeaderName(header.Name) {
			return fmt.Errorf("%s header[%d] has invalid name", scope, i)
		}
	}
	return nil
}

func validateHeaderNames(names []string, scope string) error {
	for i, name := range names {
		if !isValidHeaderName(name) {
			return fmt.Errorf("%s header[%d] has invalid name", scope, i)
		}
	}
	return nil
}

func validateCIDRs(items []string, scope string) error {
	for i, item := range items {
		candidate := strings.TrimSpace(item)
		if candidate == "" {
			continue
		}
		if strings.Contains(candidate, "/") {
			if _, _, err := net.ParseCIDR(candidate); err != nil {
				return fmt.Errorf("%s cidr[%d] is invalid", scope, i)
			}
			continue
		}
		if ip := net.ParseIP(candidate); ip == nil {
			return fmt.Errorf("%s ip[%d] is invalid", scope, i)
		}
	}
	return nil
}

func validateHTTPMethods(items []string) error {
	for i, method := range items {
		value := strings.ToUpper(strings.TrimSpace(method))
		if value == "" {
			continue
		}
		if !httpMethodRegexp.MatchString(value) {
			return fmt.Errorf("traffic control allowedMethods[%d] is invalid", i)
		}
	}
	return nil
}

func validateASNs(items []string, scope string) error {
	for i, item := range items {
		candidate := strings.ToUpper(strings.TrimSpace(item))
		candidate = strings.TrimPrefix(candidate, "AS")
		if candidate == "" {
			continue
		}
		for _, ch := range candidate {
			if ch < '0' || ch > '9' {
				return fmt.Errorf("%s asn[%d] is invalid", scope, i)
			}
		}
		value, err := strconv.ParseUint(candidate, 10, 32)
		if err != nil || value == 0 {
			return fmt.Errorf("%s asn[%d] is invalid", scope, i)
		}
	}
	return nil
}

func validateRegexList(items []string, scope string) error {
	for i, item := range items {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		if _, err := regexp.Compile(value); err != nil {
			return fmt.Errorf("%s[%d] is invalid", scope, i)
		}
	}
	return nil
}

func isValidLoadBalance(strategy string) bool {
	switch strategy {
	case LoadBalanceRound, LoadBalanceWeight, LoadBalanceRandom, LoadBalanceIPHash, LoadBalanceLeast:
		return true
	default:
		return false
	}
}

func isValidHeaderName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			continue
		}
		switch ch {
		case '-', '_':
			continue
		default:
			return false
		}
	}
	return true
}

func isValidDomainPattern(domain string) bool {
	if domain == "" {
		return false
	}
	if strings.HasPrefix(domain, "*.") {
		domain = strings.TrimPrefix(domain, "*.")
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if !hostLabelRegexp.MatchString(part) || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
	}
	return true
}
