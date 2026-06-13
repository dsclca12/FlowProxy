package iprules

import (
	"testing"

	"flowproxy/internal/settings"
	"flowproxy/internal/site"
)

func TestResolveSiteIPAccess(t *testing.T) {
	input := site.Site{
		ID:           "s1",
		IPRuleSetIDs: []string{"office", "cdn"},
		IPAccess: site.IPAccessConfig{
			DenyCIDRs:           []string{"9.9.9.9"},
			AllowASNs:           []string{"AS13335"},
			DenyASNs:            []string{"AS15169"},
			DenyReputationCIDRs: []string{"198.51.100.7"},
		},
	}
	st := settings.Settings{
		IPRuleSets: []settings.IPRuleSet{
			{
				ID:                  "office",
				AllowCIDRs:          []string{"10.0.0.0/24"},
				DenyCIDRs:           []string{"8.8.8.8"},
				AllowASNs:           []string{"AS64512"},
				DenyASNs:            []string{"AS64513"},
				DenyReputationCIDRs: []string{"198.51.100.0/24"},
			},
			{
				ID:         "cdn",
				AllowCIDRs: []string{"203.0.113.0/24"},
				DenyCIDRs:  []string{"8.8.4.4"},
			},
		},
	}
	out, err := ResolveSiteIPAccess(input, st)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if len(out.IPAccess.AllowCIDRs) != 2 || out.IPAccess.AllowCIDRs[0] != "10.0.0.0/24" || out.IPAccess.AllowCIDRs[1] != "203.0.113.0/24" {
		t.Fatalf("unexpected allow cidrs: %#v", out.IPAccess.AllowCIDRs)
	}
	if len(out.IPAccess.DenyCIDRs) != 3 {
		t.Fatalf("unexpected deny cidrs: %#v", out.IPAccess.DenyCIDRs)
	}
	if len(out.IPAccess.AllowASNs) != 2 || out.IPAccess.AllowASNs[0] != "AS13335" || out.IPAccess.AllowASNs[1] != "AS64512" {
		t.Fatalf("unexpected allow asns: %#v", out.IPAccess.AllowASNs)
	}
	if len(out.IPAccess.DenyASNs) != 2 || out.IPAccess.DenyASNs[0] != "AS15169" || out.IPAccess.DenyASNs[1] != "AS64513" {
		t.Fatalf("unexpected deny asns: %#v", out.IPAccess.DenyASNs)
	}
	if len(out.IPAccess.DenyReputationCIDRs) != 2 {
		t.Fatalf("unexpected deny reputation cidrs: %#v", out.IPAccess.DenyReputationCIDRs)
	}
	if len(out.IPAccessPolicy.SourceOrder) != 3 || out.IPAccessPolicy.SourceOrder[0] != settings.IPRuleSourceSite || out.IPAccessPolicy.SourceOrder[1] != "custom:office" || out.IPAccessPolicy.SourceOrder[2] != "custom:cdn" {
		t.Fatalf("unexpected ip access policy order: %#v", out.IPAccessPolicy.SourceOrder)
	}
	if len(out.IPRuleSetIDs) != 2 || out.IPRuleSetIDs[0] != "office" || out.IPRuleSetIDs[1] != "cdn" {
		t.Fatalf("unexpected ip rule set ids: %#v", out.IPRuleSetIDs)
	}
	if out.IPRuleSetID != "office" {
		t.Fatalf("unexpected legacy ip rule set id: %s", out.IPRuleSetID)
	}
}

func TestResolveSiteIPAccessLegacySingleID(t *testing.T) {
	input := site.Site{
		ID:          "s1",
		IPRuleSetID: "office",
	}
	st := settings.Settings{
		IPRuleSets: []settings.IPRuleSet{
			{
				ID:         "office",
				AllowCIDRs: []string{"10.0.0.0/24"},
			},
		},
	}
	out, err := ResolveSiteIPAccess(input, st)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if len(out.IPRuleSetIDs) != 1 || out.IPRuleSetIDs[0] != "office" {
		t.Fatalf("unexpected ip rule set ids: %#v", out.IPRuleSetIDs)
	}
}

func TestResolveSiteIPAccessMergesCountryAutoUpdateCIDRs(t *testing.T) {
	input := site.Site{
		ID:          "s1",
		IPRuleSetID: "office",
	}
	st := settings.Settings{
		IPRuleSets: []settings.IPRuleSet{
			{
				ID:         "office",
				AllowCIDRs: []string{"10.0.0.0/24"},
			},
		},
		IPCountryAutoUpdates: []settings.IPCountryAutoUpdate{
			{
				ID:        "cn-allow",
				Enabled:   true,
				RuleSetID: "office",
				List:      "allow",
				CIDRs:     []string{"1.0.1.0/24", "1.0.2.0/23"},
			},
			{
				ID:        "cn-deny",
				Enabled:   true,
				RuleSetID: "office",
				List:      "deny",
				CIDRs:     []string{"2.0.0.0/8"},
			},
		},
	}

	out, err := ResolveSiteIPAccess(input, st)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if len(out.IPAccess.AllowCIDRs) != 3 {
		t.Fatalf("unexpected allow cidrs: %#v", out.IPAccess.AllowCIDRs)
	}
	if len(out.IPAccess.DenyCIDRs) != 1 || out.IPAccess.DenyCIDRs[0] != "2.0.0.0/8" {
		t.Fatalf("unexpected deny cidrs: %#v", out.IPAccess.DenyCIDRs)
	}
}

func TestResolveSiteIPAccessAppliesCustomSourceOrder(t *testing.T) {
	input := site.Site{
		ID: "s1",
		IPAccess: site.IPAccessConfig{
			AllowCIDRs: []string{"203.0.113.88"},
		},
		IPRuleSetID: "office",
	}
	st := settings.Settings{
		IPRuleSourceOrder: []string{"country", "custom", "site"},
		IPRuleSets: []settings.IPRuleSet{
			{
				ID:         "office",
				AllowCIDRs: []string{"10.0.0.0/24"},
			},
		},
		IPCountryAutoUpdates: []settings.IPCountryAutoUpdate{
			{
				ID:        "office-cn-deny",
				Enabled:   true,
				RuleSetID: "office",
				List:      "deny",
				CIDRs:     []string{"203.0.113.0/24"},
			},
		},
	}

	out, err := ResolveSiteIPAccess(input, st)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if len(out.IPAccessPolicy.SourceOrder) != 3 || out.IPAccessPolicy.SourceOrder[0] != "country:office" {
		t.Fatalf("unexpected policy source order: %#v", out.IPAccessPolicy.SourceOrder)
	}
	if len(out.IPAccessPolicy.Sources) != 3 {
		t.Fatalf("unexpected policy sources: %#v", out.IPAccessPolicy.Sources)
	}
	if out.IPAccessPolicy.Sources[0].Source != "country:office" || len(out.IPAccessPolicy.Sources[0].DenyCIDRs) != 1 {
		t.Fatalf("unexpected country source rules: %#v", out.IPAccessPolicy.Sources[0])
	}
	if out.IPAccessPolicy.Sources[2].Source != settings.IPRuleSourceSite || len(out.IPAccessPolicy.Sources[2].AllowCIDRs) != 1 {
		t.Fatalf("unexpected site source rules: %#v", out.IPAccessPolicy.Sources[2])
	}
}

func TestResolveSiteIPAccessUsesRuleSetPriorityWithinCustomSource(t *testing.T) {
	input := site.Site{
		ID:           "s1",
		IPRuleSetIDs: []string{"low", "high"},
	}
	st := settings.Settings{
		IPRuleSourceOrder: []string{"custom", "site", "country"},
		IPRuleSets: []settings.IPRuleSet{
			{
				ID:             "low",
				Priority:       10,
				ConflictPolicy: settings.IPRuleConflictAllowFirst,
				DenyCIDRs: []string{
					"10.0.0.1",
				},
			},
			{
				ID:         "high",
				Priority:   100,
				AllowCIDRs: []string{"10.0.0.1"},
			},
		},
	}

	out, err := ResolveSiteIPAccess(input, st)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if len(out.IPAccessPolicy.SourceOrder) < 2 || out.IPAccessPolicy.SourceOrder[0] != "custom:high" || out.IPAccessPolicy.SourceOrder[1] != "custom:low" {
		t.Fatalf("unexpected custom policy source order: %#v", out.IPAccessPolicy.SourceOrder)
	}
	if len(out.IPAccessPolicy.Sources) < 2 || out.IPAccessPolicy.Sources[1].ConflictPolicy != settings.IPRuleConflictAllowFirst {
		t.Fatalf("unexpected conflictPolicy in custom source: %#v", out.IPAccessPolicy.Sources)
	}
}
