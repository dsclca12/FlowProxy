package iprules

import (
	"fmt"
	"sort"
	"strings"

	"flowproxy/internal/settings"
	"flowproxy/internal/site"
)

func ResolveSiteIPAccess(input site.Site, st settings.Settings) (site.Site, error) {
	selectedIDs := normalizeSelectedRuleSetIDs(input)
	ruleSetMap := buildEffectiveRuleSetMap(st)

	orderedRuleSets := make([]selectedRuleSet, 0, len(selectedIDs))
	for index, selectedID := range selectedIDs {
		matched, ok := ruleSetMap[selectedID]
		if !ok {
			return input, fmt.Errorf("ip rule set not found: %s", selectedID)
		}
		orderedRuleSets = append(orderedRuleSets, selectedRuleSet{
			orderIndex: index,
			ruleSet:    matched,
		})
	}
	sort.SliceStable(orderedRuleSets, func(i, j int) bool {
		if orderedRuleSets[i].ruleSet.Priority != orderedRuleSets[j].ruleSet.Priority {
			return orderedRuleSets[i].ruleSet.Priority > orderedRuleSets[j].ruleSet.Priority
		}
		return orderedRuleSets[i].orderIndex < orderedRuleSets[j].orderIndex
	})

	sourceOrder := settings.EffectiveIPRuleSourceOrder(st.IPRuleSourceOrder)

	allowCIDRs := []string{}
	denyCIDRs := []string{}
	allowASNs := []string{}
	denyASNs := []string{}
	denyReputationCIDRs := []string{}
	policyOrder := []string{}
	policySources := []site.IPAccessSourceRules{}
	appendPolicySource := func(sourceID string, conflictPolicy string, rules site.IPAccessConfig) {
		cleanAllow := mergeStringList(rules.AllowCIDRs)
		cleanDeny := mergeStringList(rules.DenyCIDRs)
		cleanAllowASNs := mergeStringList(rules.AllowASNs)
		cleanDenyASNs := mergeStringList(rules.DenyASNs)
		cleanDenyReputationCIDRs := mergeStringList(rules.DenyReputationCIDRs)
		if len(cleanAllow) == 0 && len(cleanDeny) == 0 && len(cleanAllowASNs) == 0 && len(cleanDenyASNs) == 0 && len(cleanDenyReputationCIDRs) == 0 {
			return
		}
		policyOrder = append(policyOrder, sourceID)
		policySources = append(policySources, site.IPAccessSourceRules{
			Source:              sourceID,
			ConflictPolicy:      normalizeRuleConflictPolicy(conflictPolicy),
			AllowCIDRs:          cleanAllow,
			DenyCIDRs:           cleanDeny,
			AllowASNs:           cleanAllowASNs,
			DenyASNs:            cleanDenyASNs,
			DenyReputationCIDRs: cleanDenyReputationCIDRs,
		})
		allowCIDRs = mergeStringList(allowCIDRs, cleanAllow)
		denyCIDRs = mergeStringList(denyCIDRs, cleanDeny)
		allowASNs = mergeStringList(allowASNs, cleanAllowASNs)
		denyASNs = mergeStringList(denyASNs, cleanDenyASNs)
		denyReputationCIDRs = mergeStringList(denyReputationCIDRs, cleanDenyReputationCIDRs)
	}

	for _, source := range sourceOrder {
		switch source {
		case settings.IPRuleSourceSite:
			appendPolicySource(settings.IPRuleSourceSite, settings.IPRuleConflictDenyFirst, site.IPAccessConfig{
				AllowCIDRs:          input.IPAccess.AllowCIDRs,
				DenyCIDRs:           input.IPAccess.DenyCIDRs,
				AllowASNs:           input.IPAccess.AllowASNs,
				DenyASNs:            input.IPAccess.DenyASNs,
				DenyReputationCIDRs: input.IPAccess.DenyReputationCIDRs,
			})
		case settings.IPRuleSourceCustom:
			for _, item := range orderedRuleSets {
				appendPolicySource(fmt.Sprintf("%s:%s", settings.IPRuleSourceCustom, item.ruleSet.ID), item.ruleSet.ConflictPolicy, site.IPAccessConfig{
					AllowCIDRs:          item.ruleSet.ManualAllowCIDRs,
					DenyCIDRs:           item.ruleSet.ManualDenyCIDRs,
					AllowASNs:           item.ruleSet.ManualAllowASNs,
					DenyASNs:            item.ruleSet.ManualDenyASNs,
					DenyReputationCIDRs: item.ruleSet.ManualDenyReputationCIDRs,
				})
			}
		case settings.IPRuleSourceCountry:
			for _, item := range orderedRuleSets {
				appendPolicySource(fmt.Sprintf("%s:%s", settings.IPRuleSourceCountry, item.ruleSet.ID), item.ruleSet.ConflictPolicy, site.IPAccessConfig{
					AllowCIDRs: item.ruleSet.CountryAllowCIDRs,
					DenyCIDRs:  item.ruleSet.CountryDenyCIDRs,
				})
			}
		default:
			continue
		}
	}

	input.IPAccess = site.IPAccessConfig{
		AllowCIDRs:          allowCIDRs,
		DenyCIDRs:           denyCIDRs,
		AllowASNs:           allowASNs,
		DenyASNs:            denyASNs,
		DenyReputationCIDRs: denyReputationCIDRs,
	}
	input.IPAccessPolicy = site.IPAccessPolicy{
		SourceOrder: policyOrder,
		Sources:     policySources,
	}
	input.IPRuleSetIDs = selectedIDs
	if len(selectedIDs) > 0 {
		input.IPRuleSetID = selectedIDs[0]
	}
	return input, nil
}

func ResolveSitesForRuntime(items []site.Site, st settings.Settings) ([]site.Site, error) {
	out := make([]site.Site, 0, len(items))
	for _, item := range items {
		resolved, err := ResolveSiteIPAccess(item, st)
		if err != nil {
			return nil, fmt.Errorf("site %s: %w", item.ID, err)
		}
		out = append(out, resolved)
	}
	return out, nil
}

type effectiveRuleSet struct {
	ID                        string
	Name                      string
	Priority                  int
	ConflictPolicy            string
	ManualAllowCIDRs          []string
	ManualDenyCIDRs           []string
	ManualAllowASNs           []string
	ManualDenyASNs            []string
	ManualDenyReputationCIDRs []string
	CountryAllowCIDRs         []string
	CountryDenyCIDRs          []string
}

type selectedRuleSet struct {
	orderIndex int
	ruleSet    effectiveRuleSet
}

func mergeStringList(items ...[]string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, list := range items {
		for _, item := range list {
			value := strings.TrimSpace(item)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func normalizeSelectedRuleSetIDs(input site.Site) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, id := range input.IPRuleSetIDs {
		value := strings.TrimSpace(id)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	legacy := strings.TrimSpace(input.IPRuleSetID)
	if legacy != "" {
		if _, ok := seen[legacy]; !ok {
			out = append(out, legacy)
		}
	}
	return out
}

func buildEffectiveRuleSetMap(st settings.Settings) map[string]effectiveRuleSet {
	out := make(map[string]effectiveRuleSet, len(st.IPRuleSets))
	for _, item := range st.IPRuleSets {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			continue
		}
		out[id] = effectiveRuleSet{
			ID:                        id,
			Name:                      strings.TrimSpace(item.Name),
			Priority:                  item.Priority,
			ConflictPolicy:            normalizeRuleConflictPolicy(item.ConflictPolicy),
			ManualAllowCIDRs:          append([]string{}, item.AllowCIDRs...),
			ManualDenyCIDRs:           append([]string{}, item.DenyCIDRs...),
			ManualAllowASNs:           append([]string{}, item.AllowASNs...),
			ManualDenyASNs:            append([]string{}, item.DenyASNs...),
			ManualDenyReputationCIDRs: append([]string{}, item.DenyReputationCIDRs...),
		}
	}
	for _, task := range st.IPCountryAutoUpdates {
		if !task.Enabled {
			continue
		}
		ruleSetID := strings.TrimSpace(task.RuleSetID)
		if ruleSetID == "" {
			continue
		}
		target, ok := out[ruleSetID]
		if !ok || len(task.CIDRs) == 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(task.List)) {
		case "deny":
			target.CountryDenyCIDRs = mergeStringList(target.CountryDenyCIDRs, task.CIDRs)
		default:
			target.CountryAllowCIDRs = mergeStringList(target.CountryAllowCIDRs, task.CIDRs)
		}
		out[ruleSetID] = target
	}
	return out
}

func normalizeRuleConflictPolicy(input string) string {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case settings.IPRuleConflictAllowFirst, "allowfirst", "allow-first":
		return settings.IPRuleConflictAllowFirst
	case settings.IPRuleConflictDenyFirst, "denyfirst", "deny-first":
		return settings.IPRuleConflictDenyFirst
	default:
		return settings.IPRuleConflictAllowFirst
	}
}
