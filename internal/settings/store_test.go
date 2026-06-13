package settings

import (
	"path/filepath"
	"testing"
	"time"
)

func TestNormalizeDefaultsLanguageToEn(t *testing.T) {
	out, err := Normalize(Settings{WebPort: 9000})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if out.Language != "en" {
		t.Fatalf("unexpected language: %s", out.Language)
	}
}

func TestNormalizeRejectsInvalidLanguage(t *testing.T) {
	_, err := Normalize(Settings{Language: "fr", WebPort: 9000})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestNormalizeAcceptsTraditionalChineseLanguage(t *testing.T) {
	out, err := Normalize(Settings{Language: "ZH-TW", WebPort: 9000})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if out.Language != "zh-tw" {
		t.Fatalf("unexpected language: %s", out.Language)
	}
}

func TestNormalizeRejectsInvalidPort(t *testing.T) {
	_, err := Normalize(Settings{Language: "zh", WebPort: 0})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestNormalizeClusterSyncDefaults(t *testing.T) {
	out, err := Normalize(Settings{
		Language: "en",
		WebPort:  9000,
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if !out.ClusterSync.CertificateSyncEnabled {
		t.Fatalf("expected certificateSyncEnabled default true")
	}
	if !out.ClusterSync.FailCloseEnabled {
		t.Fatalf("expected failCloseEnabled default true")
	}
	if out.ClusterSync.FailCloseConsecutiveFailures != 10 {
		t.Fatalf("unexpected failCloseConsecutiveFailures: %d", out.ClusterSync.FailCloseConsecutiveFailures)
	}
	if out.ClusterSync.FailCloseStaleAfter != "5m" {
		t.Fatalf("unexpected failCloseStaleAfter: %s", out.ClusterSync.FailCloseStaleAfter)
	}
}

func TestNormalizeClusterSyncRejectsInvalidValues(t *testing.T) {
	_, err := Normalize(Settings{
		Language: "en",
		WebPort:  9000,
		ClusterSync: ClusterSync{
			CertificateSyncEnabled:       true,
			FailCloseEnabled:             true,
			FailCloseConsecutiveFailures: 0,
			FailCloseStaleAfter:          "5s",
		},
	})
	if err == nil {
		t.Fatalf("expected cluster sync validation error")
	}
}

func TestNormalizeRejectsInvalidAllowCIDR(t *testing.T) {
	_, err := Normalize(Settings{
		Language: "zh",
		WebPort:  9000,
		WebAccess: WebAccess{
			AllowCIDRs: []string{"10.0.0.0/99"},
		},
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestNormalizeIPRuleSets(t *testing.T) {
	out, err := Normalize(Settings{
		Language: "zh",
		WebPort:  9000,
		IPRuleSets: []IPRuleSet{
			{
				ID:                  "office",
				Name:                "Office",
				Priority:            20,
				ConflictPolicy:      "allow-first",
				AllowCIDRs:          []string{"10.0.0.0/24", "10.0.0.0/24"},
				DenyCIDRs:           []string{"8.8.8.8"},
				AllowASNs:           []string{"as13335", "13335"},
				DenyASNs:            []string{"AS15169"},
				DenyReputationCIDRs: []string{"198.51.100.7"},
			},
		},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(out.IPRuleSets) != 1 {
		t.Fatalf("unexpected ipRuleSets: %+v", out.IPRuleSets)
	}
	if out.IPRuleSets[0].ID != "office" || len(out.IPRuleSets[0].AllowCIDRs) != 1 {
		t.Fatalf("unexpected normalized ipRuleSet: %+v", out.IPRuleSets[0])
	}
	if out.IPRuleSets[0].Priority != 20 {
		t.Fatalf("unexpected normalized ipRuleSet priority: %+v", out.IPRuleSets[0])
	}
	if out.IPRuleSets[0].ConflictPolicy != IPRuleConflictAllowFirst {
		t.Fatalf("unexpected normalized ipRuleSet conflictPolicy: %+v", out.IPRuleSets[0])
	}
	if len(out.IPRuleSets[0].AllowASNs) != 1 || out.IPRuleSets[0].AllowASNs[0] != "AS13335" {
		t.Fatalf("unexpected normalized ipRuleSet allowAsns: %+v", out.IPRuleSets[0])
	}
	if len(out.IPRuleSets[0].DenyASNs) != 1 || out.IPRuleSets[0].DenyASNs[0] != "AS15169" {
		t.Fatalf("unexpected normalized ipRuleSet denyAsns: %+v", out.IPRuleSets[0])
	}
	if len(out.IPRuleSourceOrder) != 3 || out.IPRuleSourceOrder[0] != IPRuleSourceSite || out.IPRuleSourceOrder[1] != IPRuleSourceCustom || out.IPRuleSourceOrder[2] != IPRuleSourceCountry {
		t.Fatalf("unexpected default ip rule source order: %#v", out.IPRuleSourceOrder)
	}
}

func TestNormalizeRejectsInvalidIPRuleSetASN(t *testing.T) {
	_, err := Normalize(Settings{
		Language: "zh",
		WebPort:  9000,
		IPRuleSets: []IPRuleSet{
			{
				ID:        "office",
				AllowASNs: []string{"ASX"},
			},
		},
	})
	if err == nil {
		t.Fatalf("expected invalid asn error")
	}
}

func TestNormalizeIPRuleSourceOrder(t *testing.T) {
	out, err := Normalize(Settings{
		Language:          "zh",
		WebPort:           9000,
		IPRuleSourceOrder: []string{"country", "manual"},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(out.IPRuleSourceOrder) != 3 || out.IPRuleSourceOrder[0] != IPRuleSourceCountry || out.IPRuleSourceOrder[1] != IPRuleSourceCustom || out.IPRuleSourceOrder[2] != IPRuleSourceSite {
		t.Fatalf("unexpected ip rule source order: %#v", out.IPRuleSourceOrder)
	}
}

func TestNormalizeRejectsInvalidIPRuleSourceOrder(t *testing.T) {
	_, err := Normalize(Settings{
		Language:          "zh",
		WebPort:           9000,
		IPRuleSourceOrder: []string{"country", "unknown"},
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestNormalizeIPRuleSetConflictPolicyDefaultsToAllowFirst(t *testing.T) {
	out, err := Normalize(Settings{
		Language: "zh",
		WebPort:  9000,
		IPRuleSets: []IPRuleSet{
			{
				ID:             "office",
				ConflictPolicy: "unknown",
			},
		},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if out.IPRuleSets[0].ConflictPolicy != IPRuleConflictAllowFirst {
		t.Fatalf("unexpected conflictPolicy: %+v", out.IPRuleSets[0])
	}
}

func TestNormalizeIPCountryAutoUpdates(t *testing.T) {
	out, err := Normalize(Settings{
		Language: "zh",
		WebPort:  9000,
		IPRuleSets: []IPRuleSet{
			{ID: "office"},
		},
		IPCountryAutoUpdates: []IPCountryAutoUpdate{
			{
				ID:            "cn-office",
				Enabled:       true,
				RuleSetID:     "office",
				List:          "",
				Countries:     []string{"cn", "CN"},
				Interval:      "",
				Source:        "",
				CIDRs:         []string{"1.0.1.0/24", "1.0.1.0/24"},
				LastAttemptAt: time.Now(),
				LastSyncAt:    time.Now(),
				LastError:     "  test error  ",
			},
		},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(out.IPCountryAutoUpdates) != 1 {
		t.Fatalf("unexpected ipCountryAutoUpdates: %+v", out.IPCountryAutoUpdates)
	}
	item := out.IPCountryAutoUpdates[0]
	if item.List != "allow" {
		t.Fatalf("unexpected list: %s", item.List)
	}
	if item.Interval != "24h" {
		t.Fatalf("unexpected interval: %s", item.Interval)
	}
	if item.Source != "ipdeny" {
		t.Fatalf("unexpected source: %s", item.Source)
	}
	if len(item.Countries) != 1 || item.Countries[0] != "CN" {
		t.Fatalf("unexpected countries: %#v", item.Countries)
	}
	if len(item.CIDRs) != 1 || item.CIDRs[0] != "1.0.1.0/24" {
		t.Fatalf("unexpected cidrs: %#v", item.CIDRs)
	}
	if item.LastError != "test error" {
		t.Fatalf("unexpected lastError: %s", item.LastError)
	}
}

func TestNormalizeIPCountryAutoUpdatesRejectsUnknownRuleSetID(t *testing.T) {
	_, err := Normalize(Settings{
		Language: "zh",
		WebPort:  9000,
		IPRuleSets: []IPRuleSet{
			{ID: "office"},
		},
		IPCountryAutoUpdates: []IPCountryAutoUpdate{
			{
				ID:        "cn-office",
				Enabled:   true,
				RuleSetID: "unknown",
				List:      "allow",
				Countries: []string{"CN"},
				Interval:  "24h",
				Source:    "ipdeny",
			},
		},
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestNormalizeIPCountryAutoUpdatesConvertsDenyToAllow(t *testing.T) {
	out, err := Normalize(Settings{
		Language: "zh",
		WebPort:  9000,
		IPRuleSets: []IPRuleSet{
			{ID: "office"},
		},
		IPCountryAutoUpdates: []IPCountryAutoUpdate{
			{
				ID:        "cn-office",
				Enabled:   true,
				RuleSetID: "office",
				List:      "deny",
				Countries: []string{"CN"},
				Interval:  "24h",
				Source:    "ipdeny",
			},
		},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(out.IPCountryAutoUpdates) != 1 {
		t.Fatalf("unexpected ipCountryAutoUpdates: %+v", out.IPCountryAutoUpdates)
	}
	if out.IPCountryAutoUpdates[0].List != "allow" {
		t.Fatalf("unexpected list: %s", out.IPCountryAutoUpdates[0].List)
	}
}

func TestNormalizeIPCountryAutoUpdatesRejectsInvalidList(t *testing.T) {
	_, err := Normalize(Settings{
		Language: "zh",
		WebPort:  9000,
		IPRuleSets: []IPRuleSet{
			{ID: "office"},
		},
		IPCountryAutoUpdates: []IPCountryAutoUpdate{
			{
				ID:        "cn-office",
				Enabled:   true,
				RuleSetID: "office",
				List:      "blocked",
				Countries: []string{"CN"},
				Interval:  "24h",
				Source:    "ipdeny",
			},
		},
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestStoreUpdatePersistsValue(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "settings.json")

	st, err := New(filePath, Settings{Language: "zh", WebPort: 9000})
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}

	_, err = st.Update(Settings{
		Language: "en",
		WebPort:  19000,
		WebAccess: WebAccess{
			AllowCIDRs: []string{"127.0.0.1", "10.0.0.0/24", "127.0.0.1"},
		},
	})
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}

	reloaded, err := New(filePath, Settings{Language: "zh", WebPort: 9000})
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	got := reloaded.Get()
	if got.Language != "en" {
		t.Fatalf("unexpected language: %s", got.Language)
	}
	if got.WebPort != 19000 {
		t.Fatalf("unexpected webPort: %d", got.WebPort)
	}
	if len(got.WebAccess.AllowCIDRs) != 2 {
		t.Fatalf("unexpected allow cidrs: %#v", got.WebAccess.AllowCIDRs)
	}
	if got.Backup.Interval != "24h" || got.Backup.KeepLast != 30 {
		t.Fatalf("unexpected backup defaults: %+v", got.Backup)
	}
}

func TestNormalizeBackupFields(t *testing.T) {
	out, err := Normalize(Settings{
		Language: "zh",
		WebPort:  9000,
		Backup: Backup{
			Enabled:  true,
			Interval: "12h",
			KeepLast: 7,
		},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if !out.Backup.Enabled || out.Backup.Interval != "12h" || out.Backup.KeepLast != 7 {
		t.Fatalf("unexpected backup value: %+v", out.Backup)
	}
}

func TestNormalizeBackupRejectsInvalidInterval(t *testing.T) {
	_, err := Normalize(Settings{
		Language: "zh",
		WebPort:  9000,
		Backup: Backup{
			Interval: "10s",
			KeepLast: 10,
		},
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestNormalizeAlertAndAdminTLS(t *testing.T) {
	out, err := Normalize(Settings{
		Language: "zh",
		WebPort:  9000,
		Alert: Alert{
			WebhookURL:     " https://hooks.example.com/fp ",
			Consecutive5xx: 7,
			LatencyMs:      1200,
			Cooldown:       "3m",
		},
		AdminTLS: AdminTLS{
			Enabled:        true,
			HTTPSPort:      9443,
			RedirectHTTP:   true,
			AutoSelfSigned: true,
		},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if out.Alert.WebhookURL != "https://hooks.example.com/fp" {
		t.Fatalf("unexpected alert webhook: %s", out.Alert.WebhookURL)
	}
	if out.AdminTLS.HTTPSPort != 9443 || !out.AdminTLS.Enabled {
		t.Fatalf("unexpected admin tls: %+v", out.AdminTLS)
	}
}

func TestNormalizeRejectsAdminTLSSamePortAsWeb(t *testing.T) {
	_, err := Normalize(Settings{
		Language: "zh",
		WebPort:  9000,
		AdminTLS: AdminTLS{
			Enabled:        true,
			HTTPSPort:      9000,
			AutoSelfSigned: true,
		},
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestNormalizeRejectsAdminTLSMixedCertificateSources(t *testing.T) {
	_, err := Normalize(Settings{
		Language: "zh",
		WebPort:  9000,
		AdminTLS: AdminTLS{
			Enabled:        true,
			HTTPSPort:      9443,
			AutoSelfSigned: false,
			CertificateID:  "cert-a",
			CertFile:       "/tmp/admin.crt",
			KeyFile:        "/tmp/admin.key",
		},
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}
