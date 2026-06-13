package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"flowproxy/internal/persist"
)

type Settings struct {
	Language             string                `json:"language"`
	WebPort              int                   `json:"webPort"`
	WebAccess            WebAccess             `json:"webAccess"`
	IPRuleSourceOrder    []string              `json:"ipRuleSourceOrder,omitempty"`
	IPRuleSets           []IPRuleSet           `json:"ipRuleSets,omitempty"`
	IPCountryAutoUpdates []IPCountryAutoUpdate `json:"ipCountryAutoUpdates,omitempty"`
	ClusterSync          ClusterSync           `json:"clusterSync"`
	Backup               Backup                `json:"backup"`
	Alert                Alert                 `json:"alert"`
	AdminTLS             AdminTLS              `json:"adminTls"`
	UpdatedAt            time.Time             `json:"updatedAt"`
}

const (
	IPRuleSourceSite    = "site"
	IPRuleSourceCustom  = "custom"
	IPRuleSourceCountry = "country"

	IPRuleConflictDenyFirst  = "deny_first"
	IPRuleConflictAllowFirst = "allow_first"
)

var defaultIPRuleSourceOrder = []string{
	IPRuleSourceSite,
	IPRuleSourceCustom,
	IPRuleSourceCountry,
}

type WebAccess struct {
	AllowCIDRs []string `json:"allowCidrs"`
	DenyCIDRs  []string `json:"denyCidrs"`
}

type IPRuleSet struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name,omitempty"`
	Priority            int      `json:"priority,omitempty"`
	ConflictPolicy      string   `json:"conflictPolicy,omitempty"`
	AllowCIDRs          []string `json:"allowCidrs,omitempty"`
	DenyCIDRs           []string `json:"denyCidrs,omitempty"`
	AllowASNs           []string `json:"allowAsns,omitempty"`
	DenyASNs            []string `json:"denyAsns,omitempty"`
	DenyReputationCIDRs []string `json:"denyReputationCidrs,omitempty"`
}

type IPCountryAutoUpdate struct {
	ID            string    `json:"id"`
	Enabled       bool      `json:"enabled"`
	RuleSetID     string    `json:"ruleSetId"`
	List          string    `json:"list"`
	Countries     []string  `json:"countries,omitempty"`
	IncludeIPv6   bool      `json:"includeIpv6,omitempty"`
	Interval      string    `json:"interval,omitempty"`
	Source        string    `json:"source,omitempty"`
	CIDRs         []string  `json:"cidrs,omitempty"`
	LastAttemptAt time.Time `json:"lastAttemptAt,omitempty"`
	LastSyncAt    time.Time `json:"lastSyncAt,omitempty"`
	LastError     string    `json:"lastError,omitempty"`
}

type Backup struct {
	Enabled  bool   `json:"enabled"`
	Interval string `json:"interval"`
	KeepLast int    `json:"keepLast"`
}

type ClusterSync struct {
	CertificateSyncEnabled       bool   `json:"certificateSyncEnabled"`
	FailCloseEnabled             bool   `json:"failCloseEnabled"`
	FailCloseConsecutiveFailures int    `json:"failCloseConsecutiveFailures"`
	FailCloseStaleAfter          string `json:"failCloseStaleAfter"`
}

type Alert struct {
	WebhookURL     string `json:"webhookUrl"`
	Consecutive5xx int    `json:"consecutive5xx"`
	LatencyMs      int    `json:"latencyMs"`
	Cooldown       string `json:"cooldown"`
}

type AdminTLS struct {
	Enabled        bool   `json:"enabled"`
	HTTPSPort      int    `json:"httpsPort"`
	RedirectHTTP   bool   `json:"redirectHttp"`
	AutoSelfSigned bool   `json:"autoSelfSigned"`
	CertificateID  string `json:"certificateId"`
	CertFile       string `json:"certFile"`
	KeyFile        string `json:"keyFile"`
}

type Store struct {
	mu    sync.RWMutex
	blob  persist.BlobStore
	value Settings
}

func New(filePath string, defaults Settings) (*Store, error) {
	return NewWithBlob(persist.NewFileBlobStore(filePath), defaults)
}

func NewWithBlob(blob persist.BlobStore, defaults Settings) (*Store, error) {
	normalized, err := Normalize(defaults)
	if err != nil {
		return nil, err
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = time.Now().UTC()
	}

	s := &Store{
		blob:  blob,
		value: normalized,
	}
	if s.blob == nil {
		return nil, fmt.Errorf("settings blob backend is required")
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSettings(s.value)
}

func (s *Store) Reload() error {
	return s.load()
}

func (s *Store) Update(next Settings) (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	normalized, err := Normalize(next)
	if err != nil {
		return Settings{}, err
	}
	normalized.UpdatedAt = time.Now().UTC()
	s.value = normalized
	if err := s.saveLocked(); err != nil {
		return Settings{}, err
	}
	return cloneSettings(s.value), nil
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.blob.Load(context.Background())
	if err != nil {
		if persist.IsNotFound(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}

	current := s.value
	if err := json.Unmarshal(data, &current); err != nil {
		return err
	}
	normalized, err := Normalize(current)
	if err != nil {
		return err
	}
	if current.UpdatedAt.IsZero() {
		normalized.UpdatedAt = time.Now().UTC()
	} else {
		normalized.UpdatedAt = current.UpdatedAt.UTC()
	}
	s.value = normalized
	return nil
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.value, "", "  ")
	if err != nil {
		return err
	}
	return s.blob.Save(context.Background(), data)
}

func Normalize(input Settings) (Settings, error) {
	lang := strings.ToLower(strings.TrimSpace(input.Language))
	if lang == "" {
		lang = "en"
	}
	if lang != "zh" && lang != "zh-tw" && lang != "en" {
		return Settings{}, fmt.Errorf("language must be zh, zh-tw or en")
	}

	if input.WebPort < 1 || input.WebPort > 65535 {
		return Settings{}, fmt.Errorf("webPort must be within 1-65535")
	}

	allow, err := normalizeIPRules(input.WebAccess.AllowCIDRs)
	if err != nil {
		return Settings{}, fmt.Errorf("allowCidrs: %w", err)
	}
	deny, err := normalizeIPRules(input.WebAccess.DenyCIDRs)
	if err != nil {
		return Settings{}, fmt.Errorf("denyCidrs: %w", err)
	}
	ipRuleSets, err := normalizeIPRuleSets(input.IPRuleSets)
	if err != nil {
		return Settings{}, fmt.Errorf("ipRuleSets: %w", err)
	}
	ipRuleSourceOrder, err := normalizeIPRuleSourceOrder(input.IPRuleSourceOrder)
	if err != nil {
		return Settings{}, fmt.Errorf("ipRuleSourceOrder: %w", err)
	}
	ipCountryAutoUpdates, err := normalizeIPCountryAutoUpdates(input.IPCountryAutoUpdates, ipRuleSets)
	if err != nil {
		return Settings{}, fmt.Errorf("ipCountryAutoUpdates: %w", err)
	}
	backupCfg, err := normalizeBackup(input.Backup)
	if err != nil {
		return Settings{}, fmt.Errorf("backup: %w", err)
	}
	clusterSyncCfg, err := normalizeClusterSync(input.ClusterSync)
	if err != nil {
		return Settings{}, fmt.Errorf("clusterSync: %w", err)
	}
	alertCfg, err := normalizeAlert(input.Alert)
	if err != nil {
		return Settings{}, fmt.Errorf("alert: %w", err)
	}
	adminTLSCfg, err := normalizeAdminTLS(input.AdminTLS)
	if err != nil {
		return Settings{}, fmt.Errorf("adminTls: %w", err)
	}
	if adminTLSCfg.Enabled && adminTLSCfg.HTTPSPort == input.WebPort {
		return Settings{}, fmt.Errorf("adminTls.httpsPort cannot be the same as webPort")
	}

	return Settings{
		Language: lang,
		WebPort:  input.WebPort,
		WebAccess: WebAccess{
			AllowCIDRs: allow,
			DenyCIDRs:  deny,
		},
		IPRuleSourceOrder:    ipRuleSourceOrder,
		IPRuleSets:           ipRuleSets,
		IPCountryAutoUpdates: ipCountryAutoUpdates,
		ClusterSync:          clusterSyncCfg,
		Backup:               backupCfg,
		Alert:                alertCfg,
		AdminTLS:             adminTLSCfg,
		UpdatedAt:            input.UpdatedAt.UTC(),
	}, nil
}

func normalizeIPRuleSets(items []IPRuleSet) ([]IPRuleSet, error) {
	out := make([]IPRuleSet, 0, len(items))
	seen := map[string]struct{}{}
	for i, item := range items {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			return nil, fmt.Errorf("item[%d].id is required", i)
		}
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("duplicate id: %s", id)
		}
		allow, err := normalizeIPRules(item.AllowCIDRs)
		if err != nil {
			return nil, fmt.Errorf("item[%d].allowCidrs: %w", i, err)
		}
		deny, err := normalizeIPRules(item.DenyCIDRs)
		if err != nil {
			return nil, fmt.Errorf("item[%d].denyCidrs: %w", i, err)
		}
		allowASNs, err := normalizeASNRules(item.AllowASNs)
		if err != nil {
			return nil, fmt.Errorf("item[%d].allowAsns: %w", i, err)
		}
		denyASNs, err := normalizeASNRules(item.DenyASNs)
		if err != nil {
			return nil, fmt.Errorf("item[%d].denyAsns: %w", i, err)
		}
		denyReputationCIDRs, err := normalizeIPRules(item.DenyReputationCIDRs)
		if err != nil {
			return nil, fmt.Errorf("item[%d].denyReputationCidrs: %w", i, err)
		}
		conflictPolicy := normalizeIPRuleConflictPolicy(item.ConflictPolicy)
		seen[id] = struct{}{}
		out = append(out, IPRuleSet{
			ID:                  id,
			Name:                strings.TrimSpace(item.Name),
			Priority:            item.Priority,
			ConflictPolicy:      conflictPolicy,
			AllowCIDRs:          allow,
			DenyCIDRs:           deny,
			AllowASNs:           allowASNs,
			DenyASNs:            denyASNs,
			DenyReputationCIDRs: denyReputationCIDRs,
		})
	}
	return out, nil
}

func normalizeASNRules(items []string) ([]string, error) {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		candidate := strings.ToUpper(strings.TrimSpace(item))
		if candidate == "" {
			continue
		}
		candidate = strings.TrimPrefix(candidate, "AS")
		if candidate == "" {
			return nil, fmt.Errorf("invalid asn: %s", item)
		}
		for _, ch := range candidate {
			if ch < '0' || ch > '9' {
				return nil, fmt.Errorf("invalid asn: %s", item)
			}
		}
		value, err := strconv.ParseUint(candidate, 10, 32)
		if err != nil || value == 0 {
			return nil, fmt.Errorf("invalid asn: %s", item)
		}
		canonical := fmt.Sprintf("AS%d", value)
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out, nil
}

func normalizeIPRules(items []string) ([]string, error) {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		candidate := strings.TrimSpace(item)
		if candidate == "" {
			continue
		}

		canonical := candidate
		if strings.Contains(candidate, "/") {
			_, network, err := net.ParseCIDR(candidate)
			if err != nil {
				return nil, fmt.Errorf("invalid cidr: %s", candidate)
			}
			canonical = network.String()
		} else {
			ip := net.ParseIP(candidate)
			if ip == nil {
				return nil, fmt.Errorf("invalid ip: %s", candidate)
			}
			canonical = ip.String()
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out, nil
}

func normalizeIPRuleSourceOrder(items []string) ([]string, error) {
	if len(items) == 0 {
		return append([]string{}, defaultIPRuleSourceOrder...), nil
	}

	out := make([]string, 0, len(defaultIPRuleSourceOrder))
	seen := map[string]struct{}{}
	for i, item := range items {
		source := normalizeIPRuleSource(item)
		if source == "" {
			return nil, fmt.Errorf("item[%d] must be site, custom or country", i)
		}
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}
		out = append(out, source)
	}
	for _, fallback := range defaultIPRuleSourceOrder {
		if _, ok := seen[fallback]; ok {
			continue
		}
		out = append(out, fallback)
	}
	return out, nil
}

func EffectiveIPRuleSourceOrder(items []string) []string {
	order, err := normalizeIPRuleSourceOrder(items)
	if err != nil {
		return append([]string{}, defaultIPRuleSourceOrder...)
	}
	return order
}

func normalizeIPRuleSource(input string) string {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case IPRuleSourceSite:
		return IPRuleSourceSite
	case IPRuleSourceCustom, "manual", "ruleset", "rule_set":
		return IPRuleSourceCustom
	case IPRuleSourceCountry, "geo":
		return IPRuleSourceCountry
	default:
		return ""
	}
}

func normalizeIPRuleConflictPolicy(input string) string {
	value := strings.ToLower(strings.TrimSpace(input))
	switch value {
	case "", IPRuleConflictAllowFirst, "allowfirst", "allow-first":
		return IPRuleConflictAllowFirst
	case IPRuleConflictDenyFirst, "denyfirst", "deny-first":
		return IPRuleConflictDenyFirst
	default:
		return IPRuleConflictAllowFirst
	}
}

func normalizeIPCountryAutoUpdates(items []IPCountryAutoUpdate, ruleSets []IPRuleSet) ([]IPCountryAutoUpdate, error) {
	out := make([]IPCountryAutoUpdate, 0, len(items))
	seen := map[string]struct{}{}
	ruleSetIDMap := map[string]struct{}{}
	for _, item := range ruleSets {
		ruleSetIDMap[item.ID] = struct{}{}
	}
	for i, item := range items {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			return nil, fmt.Errorf("item[%d].id is required", i)
		}
		key := strings.ToLower(id)
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("duplicate id: %s", id)
		}
		ruleSetID := strings.TrimSpace(item.RuleSetID)
		if ruleSetID == "" {
			return nil, fmt.Errorf("item[%d].ruleSetId is required", i)
		}
		if _, ok := ruleSetIDMap[ruleSetID]; !ok {
			return nil, fmt.Errorf("item[%d].ruleSetId not found in ipRuleSets: %s", i, ruleSetID)
		}

		list := strings.ToLower(strings.TrimSpace(item.List))
		if list == "" || list == "deny" {
			list = "allow"
		}
		if list != "allow" {
			return nil, fmt.Errorf("item[%d].list must be allow", i)
		}

		countries, err := normalizeCountryCodes(item.Countries)
		if err != nil {
			return nil, fmt.Errorf("item[%d].countries: %w", i, err)
		}
		if len(countries) == 0 {
			return nil, fmt.Errorf("item[%d].countries is required", i)
		}

		interval := strings.TrimSpace(item.Interval)
		if interval == "" {
			interval = "24h"
		}
		d, err := time.ParseDuration(interval)
		if err != nil {
			return nil, fmt.Errorf("item[%d].interval is invalid duration: %w", i, err)
		}
		if d < 5*time.Minute {
			return nil, fmt.Errorf("item[%d].interval must be >= 5m", i)
		}

		source := strings.ToLower(strings.TrimSpace(item.Source))
		if source == "" {
			source = "ipdeny"
		}
		if source != "ipdeny" {
			return nil, fmt.Errorf("item[%d].source must be ipdeny", i)
		}

		cidrs, err := normalizeIPRules(item.CIDRs)
		if err != nil {
			return nil, fmt.Errorf("item[%d].cidrs: %w", i, err)
		}

		seen[key] = struct{}{}
		out = append(out, IPCountryAutoUpdate{
			ID:            id,
			Enabled:       item.Enabled,
			RuleSetID:     ruleSetID,
			List:          list,
			Countries:     countries,
			IncludeIPv6:   item.IncludeIPv6,
			Interval:      interval,
			Source:        source,
			CIDRs:         cidrs,
			LastAttemptAt: item.LastAttemptAt.UTC(),
			LastSyncAt:    item.LastSyncAt.UTC(),
			LastError:     strings.TrimSpace(item.LastError),
		})
	}
	return out, nil
}

func normalizeCountryCodes(items []string) ([]string, error) {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		candidate := strings.ToUpper(strings.TrimSpace(item))
		if candidate == "" {
			continue
		}
		if len(candidate) != 2 {
			return nil, fmt.Errorf("invalid country code: %s", item)
		}
		for _, ch := range candidate {
			if ch < 'A' || ch > 'Z' {
				return nil, fmt.Errorf("invalid country code: %s", item)
			}
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out, nil
}

func cloneSettings(in Settings) Settings {
	out := in
	out.WebAccess.AllowCIDRs = append([]string{}, in.WebAccess.AllowCIDRs...)
	out.WebAccess.DenyCIDRs = append([]string{}, in.WebAccess.DenyCIDRs...)
	out.IPRuleSourceOrder = append([]string{}, in.IPRuleSourceOrder...)
	out.IPRuleSets = make([]IPRuleSet, 0, len(in.IPRuleSets))
	for _, item := range in.IPRuleSets {
		out.IPRuleSets = append(out.IPRuleSets, IPRuleSet{
			ID:                  item.ID,
			Name:                item.Name,
			Priority:            item.Priority,
			ConflictPolicy:      item.ConflictPolicy,
			AllowCIDRs:          append([]string{}, item.AllowCIDRs...),
			DenyCIDRs:           append([]string{}, item.DenyCIDRs...),
			AllowASNs:           append([]string{}, item.AllowASNs...),
			DenyASNs:            append([]string{}, item.DenyASNs...),
			DenyReputationCIDRs: append([]string{}, item.DenyReputationCIDRs...),
		})
	}
	out.IPCountryAutoUpdates = make([]IPCountryAutoUpdate, 0, len(in.IPCountryAutoUpdates))
	for _, item := range in.IPCountryAutoUpdates {
		out.IPCountryAutoUpdates = append(out.IPCountryAutoUpdates, IPCountryAutoUpdate{
			ID:            item.ID,
			Enabled:       item.Enabled,
			RuleSetID:     item.RuleSetID,
			List:          item.List,
			Countries:     append([]string{}, item.Countries...),
			IncludeIPv6:   item.IncludeIPv6,
			Interval:      item.Interval,
			Source:        item.Source,
			CIDRs:         append([]string{}, item.CIDRs...),
			LastAttemptAt: item.LastAttemptAt,
			LastSyncAt:    item.LastSyncAt,
			LastError:     item.LastError,
		})
	}
	out.ClusterSync = in.ClusterSync
	return out
}

func normalizeBackup(input Backup) (Backup, error) {
	interval := strings.TrimSpace(input.Interval)
	if interval == "" {
		interval = "24h"
	}
	d, err := time.ParseDuration(interval)
	if err != nil {
		return Backup{}, fmt.Errorf("interval is invalid duration: %w", err)
	}
	if d < time.Minute {
		return Backup{}, fmt.Errorf("interval must be >= 1m")
	}

	keepLast := input.KeepLast
	if keepLast == 0 {
		keepLast = 30
	}
	if keepLast < 1 || keepLast > 1000 {
		return Backup{}, fmt.Errorf("keepLast must be within 1-1000")
	}

	return Backup{
		Enabled:  input.Enabled,
		Interval: interval,
		KeepLast: keepLast,
	}, nil
}

func normalizeClusterSync(input ClusterSync) (ClusterSync, error) {
	// Backward-compatible migration for settings files created before clusterSync existed.
	if !input.CertificateSyncEnabled && !input.FailCloseEnabled && input.FailCloseConsecutiveFailures == 0 && strings.TrimSpace(input.FailCloseStaleAfter) == "" {
		input.CertificateSyncEnabled = true
		input.FailCloseEnabled = true
	}

	failCloseConsecutive := input.FailCloseConsecutiveFailures
	if failCloseConsecutive <= 0 {
		failCloseConsecutive = 10
	}
	if failCloseConsecutive > 100000 {
		return ClusterSync{}, fmt.Errorf("failCloseConsecutiveFailures must be within 1-100000")
	}

	failCloseStaleAfter := strings.TrimSpace(input.FailCloseStaleAfter)
	if failCloseStaleAfter == "" {
		failCloseStaleAfter = "5m"
	}
	staleAfter, err := time.ParseDuration(failCloseStaleAfter)
	if err != nil {
		return ClusterSync{}, fmt.Errorf("failCloseStaleAfter is invalid duration: %w", err)
	}
	if staleAfter < 30*time.Second {
		return ClusterSync{}, fmt.Errorf("failCloseStaleAfter must be >= 30s")
	}

	return ClusterSync{
		CertificateSyncEnabled:       input.CertificateSyncEnabled,
		FailCloseEnabled:             input.FailCloseEnabled,
		FailCloseConsecutiveFailures: failCloseConsecutive,
		FailCloseStaleAfter:          failCloseStaleAfter,
	}, nil
}

func normalizeAlert(input Alert) (Alert, error) {
	webhook := strings.TrimSpace(input.WebhookURL)
	consecutive := input.Consecutive5xx
	if consecutive <= 0 {
		consecutive = 10
	}
	if consecutive > 100000 {
		return Alert{}, fmt.Errorf("consecutive5xx must be within 1-100000")
	}
	latency := input.LatencyMs
	if latency < 0 {
		return Alert{}, fmt.Errorf("latencyMs must be >= 0")
	}
	cooldown := strings.TrimSpace(input.Cooldown)
	if cooldown == "" {
		cooldown = "5m"
	}
	d, err := time.ParseDuration(cooldown)
	if err != nil {
		return Alert{}, fmt.Errorf("cooldown is invalid duration: %w", err)
	}
	if d <= 0 {
		return Alert{}, fmt.Errorf("cooldown must be > 0")
	}
	return Alert{
		WebhookURL:     webhook,
		Consecutive5xx: consecutive,
		LatencyMs:      latency,
		Cooldown:       cooldown,
	}, nil
}

func normalizeAdminTLS(input AdminTLS) (AdminTLS, error) {
	certificateID := strings.TrimSpace(input.CertificateID)
	certFile := strings.TrimSpace(input.CertFile)
	keyFile := strings.TrimSpace(input.KeyFile)
	autoSelfSigned := input.AutoSelfSigned
	if !input.Enabled {
		return AdminTLS{
			Enabled:        false,
			HTTPSPort:      9443,
			RedirectHTTP:   false,
			AutoSelfSigned: autoSelfSigned,
			CertificateID:  certificateID,
			CertFile:       certFile,
			KeyFile:        keyFile,
		}, nil
	}
	port := input.HTTPSPort
	if port == 0 {
		port = 9443
	}
	if port < 1 || port > 65535 {
		return AdminTLS{}, fmt.Errorf("httpsPort must be within 1-65535")
	}
	if (certFile == "") != (keyFile == "") {
		return AdminTLS{}, fmt.Errorf("certFile and keyFile must be configured together")
	}
	hasExternal := certFile != "" && keyFile != ""
	hasManagedCert := certificateID != ""
	if hasExternal && hasManagedCert {
		return AdminTLS{}, fmt.Errorf("certificateId cannot be used together with certFile/keyFile")
	}
	if !hasExternal && !hasManagedCert && !autoSelfSigned {
		return AdminTLS{}, fmt.Errorf("autoSelfSigned must be enabled when certFile/keyFile are empty")
	}
	return AdminTLS{
		Enabled:        true,
		HTTPSPort:      port,
		RedirectHTTP:   input.RedirectHTTP,
		AutoSelfSigned: autoSelfSigned,
		CertificateID:  certificateID,
		CertFile:       certFile,
		KeyFile:        keyFile,
	}, nil
}
