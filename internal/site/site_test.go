package site

import "testing"

func TestValidate(t *testing.T) {
	valid := Site{
		Domain:            "example.com",
		AdditionalDomains: []string{"api.example.com", "*.example.com"},
		Upstreams: []Upstream{
			{URL: "http://127.0.0.1:8080", Weight: 2},
			{URL: "http://127.0.0.1:8081", Weight: 1},
		},
		Routes: []RouteRule{
			{
				Path:               "/api",
				Match:              MatchPrefix,
				Upstream:           "http://127.0.0.1:9000",
				RewritePattern:     "^/api",
				RewriteReplacement: "",
			},
		},
		RateLimit: RateLimitConfig{
			Enabled:           true,
			RequestsPerMinute: 60,
			Burst:             20,
			AutoBlock: AutoBlockConfig{
				Enabled:                true,
				ViolationThreshold:     5,
				ViolationWindowSeconds: 60,
				BlockSeconds:           600,
			},
		},
		TrafficControl: TrafficControlConfig{
			MaxConcurrentRequests: 100,
			AllowedMethods:        []string{"get", "post"},
		},
		IPAccess: IPAccessConfig{
			AllowCIDRs:          []string{"10.0.0.0/24"},
			DenyCIDRs:           []string{"10.0.0.2"},
			AllowASNs:           []string{"AS13335"},
			DenyASNs:            []string{"15169"},
			DenyReputationCIDRs: []string{"198.51.100.7"},
		},
		BasicAuth: BasicAuthConfig{
			Enabled:      true,
			Username:     "admin",
			PasswordHash: "$2a$10$4gEU7wM.nCkfE7PTw1QANeZ1xk0W6cCy0s2g0Ar2td4wiLBbQvWnC",
		},
		Security: SecurityConfig{
			EnableSecurityHeaders: true,
			BlockUserAgentPatterns: []string{
				`(?i)sqlmap`,
			},
		},
	}
	if err := Validate(valid); err != nil {
		t.Fatalf("expected valid site: %v", err)
	}

	invalid := Site{
		Domain:   "example.com",
		Upstream: "127.0.0.1:8080",
	}
	if err := Validate(invalid); err == nil {
		t.Fatalf("expected invalid site")
	}
}

func TestValidate_L4TCP(t *testing.T) {
	s := Site{
		Protocol:   "tcp",
		ListenPort: 3307,
		Upstream:   "192.168.1.100:3306",
	}
	if err := Validate(s); err != nil {
		t.Fatalf("expected valid TCP L4 site: %v", err)
	}
}

func TestValidate_L4UDP(t *testing.T) {
	s := Site{
		Protocol:   "udp",
		ListenPort: 5353,
		Upstream:   "192.168.1.100:53",
	}
	if err := Validate(s); err != nil {
		t.Fatalf("expected valid UDP L4 site: %v", err)
	}
}

func TestValidate_L4TLS(t *testing.T) {
	s := Site{
		Protocol:   "tls",
		ListenPort: 8443,
		Upstream:   "tls://192.168.1.100:443",
	}
	if err := Validate(s); err != nil {
		t.Fatalf("expected valid TLS L4 site: %v", err)
	}
}

func TestValidate_L4MissingListenPort(t *testing.T) {
	s := Site{
		Protocol: "tcp",
		Upstream: "192.168.1.100:3306",
	}
	if err := Validate(s); err == nil {
		t.Fatal("expected error for missing listenPort in L4 site")
	}
}

func TestValidate_L4InvalidProtocol(t *testing.T) {
	s := Site{
		Protocol:   "invalid",
		ListenPort: 1234,
		Upstream:   "192.168.1.100:3306",
	}
	if err := Validate(s); err == nil {
		t.Fatal("expected error for invalid L4 protocol")
	}
}

func TestValidate_L4WithURLScheme(t *testing.T) {
	s := Site{
		Protocol:   "tcp",
		ListenPort: 3307,
		Upstream:   "tcp://192.168.1.100:3306",
	}
	if err := Validate(s); err != nil {
		t.Fatalf("expected valid L4 site with URL scheme: %v", err)
	}
}

func TestValidate_L4Upstreams(t *testing.T) {
	s := Site{
		Protocol:   "tcp",
		ListenPort: 3307,
		Upstreams: []Upstream{
			{URL: "192.168.1.100:3306"},
		},
	}
	if err := Validate(s); err != nil {
		t.Fatalf("expected valid L4 site with upstreams list: %v", err)
	}
}

func TestValidateRejectsInvalidCIDR(t *testing.T) {
	in := Site{
		Domain:   "example.com",
		Upstream: "http://127.0.0.1:8080",
		IPAccess: IPAccessConfig{
			AllowCIDRs: []string{"10.0.0.0/33"},
		},
	}
	if err := Validate(in); err == nil {
		t.Fatalf("expected cidr validation error")
	}
}

func TestValidateRejectsInvalidASN(t *testing.T) {
	in := Site{
		Domain:   "example.com",
		Upstream: "http://127.0.0.1:8080",
		IPAccess: IPAccessConfig{
			AllowASNs: []string{"ASXYZ"},
		},
	}
	if err := Validate(in); err == nil {
		t.Fatalf("expected asn validation error")
	}
}

func TestValidateAllowsListenPortWithoutDomain(t *testing.T) {
	in := Site{
		ListenPort: 2001,
		Upstream:   "http://127.0.0.1:8080",
	}
	if err := Validate(in); err != nil {
		t.Fatalf("expected valid site with listen port only: %v", err)
	}
}

func TestValidateRejectsWhenDomainAndListenPortAreMissing(t *testing.T) {
	in := Site{
		Upstream: "http://127.0.0.1:8080",
	}
	if err := Validate(in); err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestValidateRejectsInvalidAllowedMethod(t *testing.T) {
	in := Site{
		Domain:   "example.com",
		Upstream: "http://127.0.0.1:8080",
		TrafficControl: TrafficControlConfig{
			AllowedMethods: []string{"GET", "BAD METHOD"},
		},
	}
	if err := Validate(in); err == nil {
		t.Fatalf("expected method validation error")
	}
}

func TestValidateRejectsInvalidBlockedUserAgentPattern(t *testing.T) {
	in := Site{
		Domain:   "example.com",
		Upstream: "http://127.0.0.1:8080",
		Security: SecurityConfig{
			BlockUserAgentPatterns: []string{"("},
		},
	}
	if err := Validate(in); err == nil {
		t.Fatalf("expected regex validation error")
	}
}

func TestValidateRejectsAutoBlockWithoutRateLimit(t *testing.T) {
	in := Site{
		Domain:   "example.com",
		Upstream: "http://127.0.0.1:8080",
		RateLimit: RateLimitConfig{
			Enabled: false,
			AutoBlock: AutoBlockConfig{
				Enabled: true,
			},
		},
	}
	if err := Validate(in); err == nil {
		t.Fatalf("expected auto block validation error")
	}
}

func TestValidateRejectsNegativeAutoBlockFields(t *testing.T) {
	in := Site{
		Domain:   "example.com",
		Upstream: "http://127.0.0.1:8080",
		RateLimit: RateLimitConfig{
			Enabled: true,
			AutoBlock: AutoBlockConfig{
				Enabled:                true,
				ViolationThreshold:     -1,
				ViolationWindowSeconds: -1,
				BlockSeconds:           -1,
			},
		},
	}
	if err := Validate(in); err == nil {
		t.Fatalf("expected negative auto block validation error")
	}
}

func TestValidateCanaryRequiresTrigger(t *testing.T) {
	in := Site{
		Domain:   "example.com",
		Upstream: "http://127.0.0.1:8080",
		Canary: CanaryConfig{
			Enabled:  true,
			Upstream: "http://127.0.0.1:8081",
		},
	}
	if err := Validate(in); err == nil {
		t.Fatalf("expected canary validation error")
	}
}

func TestValidateRejectsNegativeCacheFields(t *testing.T) {
	in := Site{
		Domain:   "example.com",
		Upstream: "http://127.0.0.1:8080",
		Cache: CacheConfig{
			Enabled:      true,
			TTLSeconds:   -1,
			MaxEntries:   -1,
			MaxBodyBytes: -1,
		},
	}
	if err := Validate(in); err == nil {
		t.Fatalf("expected cache validation error")
	}
}

func TestValidateRouteConditionFields(t *testing.T) {
	in := Site{
		Domain:   "example.com",
		Upstream: "http://127.0.0.1:8080",
		Routes: []RouteRule{
			{
				Path:        "/api",
				Match:       MatchPrefix,
				Methods:     []string{"GET"},
				Header:      "X-Version",
				HeaderValue: "v2",
				Cookie:      "beta",
				CookieValue: "1",
				Query:       "stage",
				QueryValue:  "canary",
				Upstream:    "http://127.0.0.1:8081",
			},
		},
	}
	if err := Validate(in); err != nil {
		t.Fatalf("expected valid route condition fields, got %v", err)
	}
}

func TestValidateRejectsInvalidTimeoutFields(t *testing.T) {
	in := Site{
		Domain:   "example.com",
		Upstream: "http://127.0.0.1:8080",
		Timeouts: TimeoutConfig{
			RequestMillis: -1,
		},
	}
	if err := Validate(in); err == nil {
		t.Fatalf("expected timeout validation error")
	}
}

func TestValidateRejectsInvalidRetryBackoff(t *testing.T) {
	in := Site{
		Domain:   "example.com",
		Upstream: "http://127.0.0.1:8080",
		Resilience: ResilienceConfig{
			Retry: RetryConfig{
				Enabled:         true,
				Attempts:        2,
				RetryOnStatuses: []int{503},
				BackoffStrategy: "linear",
			},
		},
	}
	if err := Validate(in); err == nil {
		t.Fatalf("expected retry backoff validation error")
	}
}
