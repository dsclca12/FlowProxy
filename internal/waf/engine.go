package waf

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// maxBodyRead is the maximum body size to read for WAF inspection.
// Bodies larger than this are truncated, reducing the risk of memory exhaustion.
const maxBodyRead = 1 << 20 // 1 MiB

// Engine is a WAF rule engine that inspects HTTP requests against a set of rules.
type Engine struct {
	config          Config
	rules           []Rule
	excludeCompiled []*regexp.Regexp
	severityLevel   int
}

// NewEngine creates a new WAF engine from configuration.
func NewEngine(cfg Config) (*Engine, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}

	engine := &Engine{
		config: cfg,
		rules:  make([]Rule, 0),
	}

	// Load built-in rules if enabled
	engine.rules = append(engine.rules, BuiltinRules()...)

	// Append custom rules
	for _, rule := range cfg.CustomRules {
		if rule.Compiled != nil {
			engine.rules = append(engine.rules, rule)
		}
	}

	// Remove excluded rules
	if len(cfg.ExcludeRules) > 0 {
		excludeSet := make(map[string]struct{}, len(cfg.ExcludeRules))
		for _, id := range cfg.ExcludeRules {
			excludeSet[strings.TrimSpace(id)] = struct{}{}
		}
		filtered := make([]Rule, 0, len(engine.rules))
		for _, rule := range engine.rules {
			if _, excluded := excludeSet[rule.ID]; !excluded {
				filtered = append(filtered, rule)
			}
		}
		engine.rules = filtered
	}

	// Compile exclude path patterns
	engine.excludeCompiled = make([]*regexp.Regexp, 0, len(cfg.ExcludePaths))
	for _, path := range cfg.ExcludePaths {
		if path == "" {
			continue
		}
		pattern := path
		if !strings.HasPrefix(path, "^") {
			pattern = "^" + strings.ReplaceAll(regexp.QuoteMeta(path), "\\*", ".*") + "($|/)"
		}
		reg, err := regexp.Compile(pattern)
		if err == nil {
			engine.excludeCompiled = append(engine.excludeCompiled, reg)
		}
	}

	// Set severity threshold level
	engine.severityLevel = SeverityOrder[RuleSeverity(cfg.SeverityThreshold)]
	if engine.severityLevel <= 0 {
		engine.severityLevel = SeverityOrder[SeverityLow]
	}

	return engine, nil
}

// isExcludedPath checks if the request path matches any exclude patterns.
func (e *Engine) isExcludedPath(path string) bool {
	for _, pattern := range e.excludeCompiled {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

// Inspect examines an HTTP request and returns the WAF inspection result.
// The body reader should be the original request body. This function reads
// the body and replaces it with a fresh reader for downstream handlers.
func (e *Engine) Inspect(req *http.Request) *Result {
	if req == nil {
		return &Result{Blocked: false}
	}

	path := req.URL.Path
	if path == "" {
		path = "/"
	}

	// Check excluded paths
	if e.isExcludedPath(path) {
		return &Result{Blocked: false}
	}

	result := &Result{
		Blocked:    false,
		Mode:       e.config.Mode,
		Violations: make([]Violation, 0),
	}

	// Build a combined string for URI + args (URL-decoded for pattern matching)
	uriTarget := path
	if req.URL.RawQuery != "" {
		decodedQuery, queryErr := url.QueryUnescape(req.URL.RawQuery)
		if queryErr == nil {
			uriTarget = path + "?" + decodedQuery
		} else {
			uriTarget = path + "?" + req.URL.RawQuery
		}
	}

	// Read body for body-targeted rules
	bodyBytes := e.readBody(req)
	bodyStr := string(bodyBytes)

	// Build headers string
	headersStr := headersAsString(req.Header)

	// Build cookies string
	cookiesStr := cookiesAsString(req)

	// Match rules
	for _, rule := range e.rules {
		if rule.Compiled == nil {
			continue
		}

		// Check severity threshold
		if SeverityOrder[rule.Severity] < e.severityLevel {
			continue
		}

		var matched bool
		var matchedValue string

		switch rule.Target {
		case TargetURI, TargetArgs:
			if rule.Compiled.MatchString(uriTarget) {
				matched = true
				matchedValue = rule.Compiled.FindString(uriTarget)
			}
		case TargetBody:
			if rule.Compiled.MatchString(bodyStr) {
				matched = true
				matchedValue = rule.Compiled.FindString(bodyStr)
			}
		case TargetHeaders:
			if rule.Compiled.MatchString(headersStr) {
				matched = true
				matchedValue = rule.Compiled.FindString(headersStr)
			}
		case TargetCookies:
			if rule.Compiled.MatchString(cookiesStr) {
				matched = true
				matchedValue = rule.Compiled.FindString(cookiesStr)
			}
		case TargetMethod:
			if rule.Compiled.MatchString(req.Method) {
				matched = true
				matchedValue = req.Method
			}
		}

		if matched {
			result.Violations = append(result.Violations, Violation{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Category: rule.Category,
				Severity: rule.Severity,
				Target:   rule.Target,
				Matched:  truncateString(matchedValue, 80),
			})
		}
	}

	// Sort violations by severity (most severe first)
	sort.Slice(result.Violations, func(i, j int) bool {
		return SeverityOrder[result.Violations[i].Severity] > SeverityOrder[result.Violations[j].Severity]
	})

	// Determine if blocked
	if e.config.Mode == "block" && len(result.Violations) > 0 {
		result.Blocked = true
	}

	return result
}

// readBody reads the request body for inspection, then replaces it.
func (e *Engine) readBody(req *http.Request) []byte {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, maxBodyRead))
	if err != nil {
		return nil
	}
	_ = req.Body.Close()

	// Replace the body with a fresh reader
	req.Body = io.NopCloser(bytes.NewReader(body))
	return body
}

// AddViolationHeaders adds WAF violation information as response headers.
func AddViolationHeaders(headers http.Header, result *Result) {
	if result == nil || len(result.Violations) == 0 {
		return
	}
	headers.Set("X-WAF-Blocked", fmtBool(result.Blocked))
	headers.Set("X-WAF-Mode", result.Mode)

	// Add the first (most severe) violation info
	v := result.Violations[0]
	headers.Set("X-WAF-Rule", v.RuleID)
	headers.Set("X-WAF-Category", string(v.Category))
	headers.Set("X-WAF-Severity", string(v.Severity))

	// If there are multiple violations, add a count
	if len(result.Violations) > 1 {
		headers.Set("X-WAF-Violations", fmtInt(len(result.Violations)))
	}
}

func fmtBool(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func fmtInt(v int) string {
	if v < 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for v >= 10 {
		buf = append([]byte{byte('0' + v%10)}, buf...)
		v /= 10
	}
	buf = append([]byte{byte('0' + v)}, buf...)
	return string(buf)
}

// headersAsString flattens request headers into a single string for pattern matching.
func headersAsString(headers http.Header) string {
	if headers == nil {
		return ""
	}
	var buf strings.Builder
	for key, values := range headers {
		for _, value := range values {
			buf.WriteString(key)
			buf.WriteString(": ")
			buf.WriteString(value)
			buf.WriteString("\n")
		}
	}
	return buf.String()
}

// cookiesAsString extracts cookies into a single string for pattern matching.
func cookiesAsString(req *http.Request) string {
	if req == nil {
		return ""
	}
	cookie := req.Header.Get("Cookie")
	if cookie == "" {
		return ""
	}
	return cookie
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
