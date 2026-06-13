// Package waf implements a Web Application Firewall with built-in and custom rules.
package waf

import (
	"fmt"
	"regexp"
	"strings"
)

// RuleSeverity represents the severity level of a WAF rule.
type RuleSeverity string

const (
	SeverityCritical RuleSeverity = "critical"
	SeverityHigh     RuleSeverity = "high"
	SeverityMedium   RuleSeverity = "medium"
	SeverityLow      RuleSeverity = "low"
)

// RuleCategory represents the category of a WAF rule.
type RuleCategory string

const (
	CategorySQLInjection      RuleCategory = "sql_injection"
	CategoryXSS               RuleCategory = "xss"
	CategoryPathTraversal     RuleCategory = "path_traversal"
	CategoryCommandInjection  RuleCategory = "command_injection"
	CategoryRFI               RuleCategory = "rfi"
	CategoryLFI               RuleCategory = "lfi"
	CategoryScanner           RuleCategory = "scanner"
	CategoryProtocolViolation RuleCategory = "protocol_violation"
	CategoryMaliciousFile     RuleCategory = "malicious_file_upload"
	CategoryLDAPInjection     RuleCategory = "ldap_injection"
)

// RuleTarget specifies where the rule pattern should be matched.
type RuleTarget string

const (
	TargetURI     RuleTarget = "uri"
	TargetArgs    RuleTarget = "args"
	TargetBody    RuleTarget = "body"
	TargetHeaders RuleTarget = "headers"
	TargetCookies RuleTarget = "cookies"
	TargetMethod  RuleTarget = "method"
)

// Rule defines a single WAF inspection rule.
type Rule struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Category RuleCategory   `json:"category"`
	Severity RuleSeverity   `json:"severity"`
	Target   RuleTarget     `json:"target"`
	Pattern  string         `json:"pattern"`
	Compiled *regexp.Regexp `json:"-"`
}

// Violation records a single WAF rule violation found during inspection.
type Violation struct {
	RuleID   string       `json:"ruleId"`
	RuleName string       `json:"ruleName"`
	Category RuleCategory `json:"category"`
	Severity RuleSeverity `json:"severity"`
	Target   RuleTarget   `json:"target"`
	Matched  string       `json:"matched,omitempty"`
}

// Result holds the complete WAF inspection result for a request.
type Result struct {
	Blocked    bool        `json:"blocked"`
	Mode       string      `json:"mode"`
	Violations []Violation `json:"violations,omitempty"`
}

// SeverityOrder maps severity to numeric order for threshold comparison.
var SeverityOrder = map[RuleSeverity]int{
	SeverityCritical: 4,
	SeverityHigh:     3,
	SeverityMedium:   2,
	SeverityLow:      1,
}

// Config defines WAF configuration for a site or globally.
type Config struct {
	Enabled           bool     `json:"enabled,omitempty"`
	Mode              string   `json:"mode,omitempty"`
	SeverityThreshold string   `json:"severityThreshold,omitempty"`
	ExcludePaths      []string `json:"excludePaths,omitempty"`
	CustomRules       []Rule   `json:"customRules,omitempty"`
	ExcludeRules      []string `json:"excludeRules,omitempty"`
}

// Normalize validates and normalizes a WAF configuration.
func (c *Config) Normalize() error {
	if !c.Enabled {
		return nil
	}
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	if c.Mode == "" {
		c.Mode = "block"
	}
	if c.Mode != "block" && c.Mode != "detect" {
		return fmt.Errorf("unsupported waf mode: %q (supported: block, detect)", c.Mode)
	}

	c.SeverityThreshold = strings.ToLower(strings.TrimSpace(c.SeverityThreshold))
	if c.SeverityThreshold == "" {
		c.SeverityThreshold = string(SeverityLow)
	}
	if _, ok := SeverityOrder[RuleSeverity(c.SeverityThreshold)]; !ok {
		return fmt.Errorf("unsupported waf severityThreshold: %q (supported: critical, high, medium, low)", c.SeverityThreshold)
	}

	// Normalize exclude paths
	cleaned := make([]string, 0, len(c.ExcludePaths))
	for _, p := range c.ExcludePaths {
		p = strings.TrimSpace(p)
		if p != "" {
			cleaned = append(cleaned, p)
		}
	}
	c.ExcludePaths = cleaned

	// Compile custom rules
	for i := range c.CustomRules {
		pattern := strings.TrimSpace(c.CustomRules[i].Pattern)
		if pattern == "" {
			continue
		}
		reg, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("waf custom rule %q: invalid pattern %q: %w", c.CustomRules[i].ID, pattern, err)
		}
		c.CustomRules[i].Compiled = reg
	}

	return nil
}

// BuiltinRules returns the default set of built-in WAF rules.
// These are carefully tuned to balance security coverage and false positive risk.
func BuiltinRules() []Rule {
	return append(
		sqlInjectionRules(),
		xssRules()...,
	)
}

// sqlInjectionRules returns SQL injection detection patterns.
func sqlInjectionRules() []Rule {
	patterns := []Rule{
		{
			ID:       "sqli-001",
			Name:     "SQL Injection - UNION SELECT",
			Category: CategorySQLInjection,
			Severity: SeverityHigh,
			Target:   TargetURI,
			Pattern:  `(?i)(\bUNION\b[^\w]+.*\bSELECT\b)`,
		},
		{
			ID:       "sqli-002",
			Name:     "SQL Injection - OR/AND with comments",
			Category: CategorySQLInjection,
			Severity: SeverityHigh,
			Target:   TargetURI,
			Pattern:  `(?i)(\bOR\b|\bAND\b)\s+['\"]?\w+['"]?\s*[=<>!]+\s*['\"]?\w*['"]?\s*(--|#|/\*)`,
		},
		{
			ID:       "sqli-003",
			Name:     "SQL Injection - sleep/pause/benchmark",
			Category: CategorySQLInjection,
			Severity: SeverityHigh,
			Target:   TargetURI,
			Pattern:  `(?i)(\bSLEEP\b|\bWAITFOR\b|\bBENCHMARK\b)\s*\(`,
		},
		{
			ID:       "sqli-004",
			Name:     "SQL Injection - information_schema access",
			Category: CategorySQLInjection,
			Severity: SeverityHigh,
			Target:   TargetURI,
			Pattern:  `(?i)(\bINFORMATION_SCHEMA\b|\bMYSQL\.\w+\b|\bPG_CATALOG\b|\bSYSCAT\b)`,
		},
		{
			ID:       "sqli-005",
			Name:     "SQL Injection - exec/xp_cmdshell/xp_regread",
			Category: CategorySQLInjection,
			Severity: SeverityCritical,
			Target:   TargetURI,
			Pattern:  `(?i)(\bEXEC\b|\bEXECUTE\b)[\s(]+.*\b(xp_cmdshell|xp_regread|xp_regwrite|sp_configure)\b`,
		},
		{
			ID:       "sqli-006",
			Name:     "SQL Injection - inline comments bypass",
			Category: CategorySQLInjection,
			Severity: SeverityMedium,
			Target:   TargetURI,
			Pattern:  `(?i)(['\"])\s*(OR|AND)\s*\1\s*[=<>]`,
		},
		{
			ID:       "sqli-007",
			Name:     "SQL Injection - hex/char based injection",
			Category: CategorySQLInjection,
			Severity: SeverityMedium,
			Target:   TargetURI,
			Pattern:  `(?i)(\b(0x[0-9a-f]{2,})\b|\bCHAR\s*\(\d+\)|\bNCHAR\s*\(\d+\)|\bUNICODE\s*\(\d+\))`,
		},
		{
			ID:       "sqli-008",
			Name:     "SQL Injection - into outfile/dumpfile",
			Category: CategorySQLInjection,
			Severity: SeverityCritical,
			Target:   TargetURI,
			Pattern:  `(?i)(\bINTO\s+(OUT|DUMP)FILE\b)`,
		},
		{
			ID:       "sqli-009",
			Name:     "SQL Injection - stacked queries",
			Category: CategorySQLInjection,
			Severity: SeverityHigh,
			Target:   TargetURI,
			Pattern:  `['\"];\s*(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|TRUNCATE)\b`,
		},
		{
			ID:       "sqli-010",
			Name:     "SQL Injection - LOAD_FILE",
			Category: CategorySQLInjection,
			Severity: SeverityHigh,
			Target:   TargetURI,
			Pattern:  `(?i)(\bLOAD_FILE\b\s*\()`,
		},
		{
			ID:       "sqli-011",
			Name:     "SQL Injection - conditional errors",
			Category: CategorySQLInjection,
			Severity: SeverityMedium,
			Target:   TargetURI,
			Pattern:  `(?i)(\bIF\b\s*\(.*?,\s*(?:SELECT|SLEEP|BENCHMARK)\b)`,
		},
	}
	return compileRules(patterns)
}

// xssRules returns XSS detection patterns.
func xssRules() []Rule {
	patterns := []Rule{
		{
			ID:       "xss-001",
			Name:     "XSS - script tag",
			Category: CategoryXSS,
			Severity: SeverityHigh,
			Target:   TargetURI,
			Pattern:  `(?i)<script[\s>/]`,
		},
		{
			ID:       "xss-002",
			Name:     "XSS - event handlers",
			Category: CategoryXSS,
			Severity: SeverityHigh,
			Target:   TargetURI,
			Pattern:  `(?i)\bon\w+\s*=\s*['\"]?[^'\"\s>]*[('\"]`,
		},
		{
			ID:       "xss-003",
			Name:     "XSS - javascript: URI",
			Category: CategoryXSS,
			Severity: SeverityHigh,
			Target:   TargetURI,
			Pattern:  `(?i)(javascript|vbscript|data):\s*\w`,
		},
		{
			ID:       "xss-004",
			Name:     "XSS - eval/setTimeout/setInterval/Function",
			Category: CategoryXSS,
			Severity: SeverityHigh,
			Target:   TargetURI,
			Pattern:  `(?i)(\beval\b|\bsetTimeout\b|\bsetInterval\b|\bnew\s+Function\b)\s*\(`,
		},
		{
			ID:       "xss-005",
			Name:     "XSS - document.cookie/document.write/location",
			Category: CategoryXSS,
			Severity: SeverityMedium,
			Target:   TargetURI,
			Pattern:  `(?i)(document\.(cookie|write|writeln|location|domain)|window\.location)\s*[=:(\[]`,
		},
		{
			ID:       "xss-006",
			Name:     "XSS - HTML encoding bypass attempts",
			Category: CategoryXSS,
			Severity: SeverityMedium,
			Target:   TargetURI,
			Pattern:  `(?i)(&lt;|&#x?[0-9a-f]{2,4};)\s*(script|iframe|img|body|div)\b`,
		},
		{
			ID:       "xss-007",
			Name:     "XSS - SVG/iframe/embed/object",
			Category: CategoryXSS,
			Severity: SeverityHigh,
			Target:   TargetURI,
			Pattern:  `(?i)<(iframe|embed|object|svg|math|meta|link|style)[\s>/]`,
		},
		{
			ID:       "xss-008",
			Name:     "XSS - CSS expression injection",
			Category: CategoryXSS,
			Severity: SeverityMedium,
			Target:   TargetURI,
			Pattern:  `(?i)(expression\s*\(|url\s*\(['\"]?\s*javascript:)`,
		},
		{
			ID:       "xss-009",
			Name:     "XSS - onerror/onload/onfocus in attributes",
			Category: CategoryXSS,
			Severity: SeverityMedium,
			Target:   TargetURI,
			Pattern:  `(?i)(\bonerror\b|\bonload\b|\bonfocus\b|\bonblur\b|\bonsubmit\b|\bonchange\b)\s*=\s*['\"]?[^'\"\s>]`,
		},
		{
			ID:       "xss-010",
			Name:     "XSS - Angular template injection",
			Category: CategoryXSS,
			Severity: SeverityMedium,
			Target:   TargetURI,
			Pattern:  `\{\{.*?\}\}`,
		},
		{
			ID:       "xss-011",
			Name:     "XSS - import/referrer policy bypass",
			Category: CategoryXSS,
			Severity: SeverityLow,
			Target:   TargetURI,
			Pattern:  `(?i)(<import\b|<link\b[^>]*rel=['\"]?import['\"]?)`,
		},
		{
			ID:       "xss-012",
			Name:     "XSS - polyglot/inline event with auto-focus",
			Category: CategoryXSS,
			Severity: SeverityHigh,
			Target:   TargetURI,
			Pattern:  `(?i)(\bautofocus\b|\bautofocus\s*=\s*['\"]?autofocus['\"]?).*?\bon\w+\s*=`,
		},
	}
	return compileRules(patterns)
}

// compileRules compiles the regex patterns for a set of rules.
func compileRules(patterns []Rule) []Rule {
	for i := range patterns {
		pattern := strings.TrimSpace(patterns[i].Pattern)
		if pattern == "" {
			continue
		}
		reg, err := regexp.Compile(pattern)
		if err == nil {
			patterns[i].Compiled = reg
		}
	}
	return patterns
}
