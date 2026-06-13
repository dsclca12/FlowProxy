package main

import (
	"strings"
	"time"

	"flowproxy/internal/config"
	"flowproxy/internal/settings"
)

func applyRuntimeOverridesFromSettings(cfg *config.Config, st settings.Settings) {
	if cfg == nil {
		return
	}
	cfg.AdminAddr = addrWithPort(cfg.AdminAddr, st.WebPort)

	if st.AdminTLS.Enabled {
		cfg.AdminHTTPSAddr = addrWithPort(cfg.AdminAddr, st.AdminTLS.HTTPSPort)
		cfg.AdminTLSRedirectHTTP = st.AdminTLS.RedirectHTTP
		cfg.AdminTLSAutoSelfSigned = st.AdminTLS.AutoSelfSigned
		cfg.AdminTLSCertificateID = strings.TrimSpace(st.AdminTLS.CertificateID)
		cfg.AdminTLSCertFile = strings.TrimSpace(st.AdminTLS.CertFile)
		cfg.AdminTLSKeyFile = strings.TrimSpace(st.AdminTLS.KeyFile)
	} else {
		cfg.AdminHTTPSAddr = ""
		cfg.AdminTLSRedirectHTTP = false
		cfg.AdminTLSCertificateID = ""
	}

	cfg.AlertWebhookURL = strings.TrimSpace(st.Alert.WebhookURL)
	cfg.AlertConsecutive5xx = st.Alert.Consecutive5xx
	cfg.AlertLatencyMs = st.Alert.LatencyMs
	if d, err := time.ParseDuration(strings.TrimSpace(st.Alert.Cooldown)); err == nil && d > 0 {
		cfg.AlertCooldown = d
	}
}

func adminTLSSettingsChanged(prev settings.AdminTLS, next settings.AdminTLS) bool {
	if prev.Enabled != next.Enabled {
		return true
	}
	if prev.HTTPSPort != next.HTTPSPort {
		return true
	}
	if prev.RedirectHTTP != next.RedirectHTTP {
		return true
	}
	if prev.AutoSelfSigned != next.AutoSelfSigned {
		return true
	}
	if strings.TrimSpace(prev.CertificateID) != strings.TrimSpace(next.CertificateID) {
		return true
	}
	if strings.TrimSpace(prev.CertFile) != strings.TrimSpace(next.CertFile) {
		return true
	}
	if strings.TrimSpace(prev.KeyFile) != strings.TrimSpace(next.KeyFile) {
		return true
	}
	return false
}
