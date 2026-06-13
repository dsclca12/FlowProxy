package main

import (
	"testing"
	"time"

	"flowproxy/internal/config"
	"flowproxy/internal/settings"
)

func TestApplyRuntimeOverridesFromSettings(t *testing.T) {
	cfg := config.Config{
		AdminAddr:              "0.0.0.0:9000",
		AdminHTTPSAddr:         ":9443",
		AdminTLSRedirectHTTP:   false,
		AdminTLSAutoSelfSigned: true,
		AlertWebhookURL:        "",
		AlertConsecutive5xx:    10,
		AlertLatencyMs:         0,
		AlertCooldown:          5 * time.Minute,
	}
	st := settings.Settings{
		WebPort: 19000,
		Alert: settings.Alert{
			WebhookURL:     "https://hooks.example.com/fp",
			Consecutive5xx: 8,
			LatencyMs:      900,
			Cooldown:       "2m",
		},
		AdminTLS: settings.AdminTLS{
			Enabled:        true,
			HTTPSPort:      19443,
			RedirectHTTP:   true,
			AutoSelfSigned: false,
			CertificateID:  "admin-cert",
			CertFile:       "/tmp/admin.crt",
			KeyFile:        "/tmp/admin.key",
		},
	}

	applyRuntimeOverridesFromSettings(&cfg, st)

	if cfg.AdminAddr != "0.0.0.0:19000" {
		t.Fatalf("unexpected admin addr: %s", cfg.AdminAddr)
	}
	if cfg.AdminHTTPSAddr != "0.0.0.0:19443" {
		t.Fatalf("unexpected admin https addr: %s", cfg.AdminHTTPSAddr)
	}
	if cfg.AdminTLSCertificateID != "admin-cert" {
		t.Fatalf("unexpected admin tls certificate id: %s", cfg.AdminTLSCertificateID)
	}
	if cfg.AlertWebhookURL != "https://hooks.example.com/fp" {
		t.Fatalf("unexpected alert webhook: %s", cfg.AlertWebhookURL)
	}
	if cfg.AlertConsecutive5xx != 8 || cfg.AlertLatencyMs != 900 {
		t.Fatalf("unexpected alert config: %+v", cfg)
	}
	if cfg.AlertCooldown != 2*time.Minute {
		t.Fatalf("unexpected alert cooldown: %v", cfg.AlertCooldown)
	}
}

func TestAdminTLSSettingsChanged(t *testing.T) {
	prev := settings.AdminTLS{Enabled: true, HTTPSPort: 9443, RedirectHTTP: false, AutoSelfSigned: true}
	next := prev
	if adminTLSSettingsChanged(prev, next) {
		t.Fatalf("expected unchanged settings")
	}
	next.RedirectHTTP = true
	if !adminTLSSettingsChanged(prev, next) {
		t.Fatalf("expected changed settings")
	}
}
