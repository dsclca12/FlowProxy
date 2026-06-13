package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"flowproxy/internal/node"
	"flowproxy/internal/persist"
	"flowproxy/internal/site"
)

var ErrNotFound = errors.New("site not found")

type Store struct {
	mu    sync.RWMutex
	blob  persist.BlobStore
	sites []site.Site
}

func New(filePath string) (*Store, error) {
	return NewWithBlob(persist.NewFileBlobStore(filePath))
}

func NewWithBlob(blob persist.BlobStore) (*Store, error) {
	if blob == nil {
		return nil, fmt.Errorf("store blob backend is required")
	}
	s := &Store{blob: blob, sites: []site.Site{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) List() []site.Site {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]site.Site, len(s.sites))
	for i := range s.sites {
		cp[i] = cloneSite(s.sites[i])
	}
	return cp
}

func (s *Store) Reload() error {
	return s.load()
}

func (s *Store) ReplaceAll(items []site.Site) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]site.Site, len(items))
	for i := range items {
		cp[i] = cloneSite(items[i])
	}
	s.sites = cp
	return s.saveLocked()
}

func (s *Store) Get(id string) (site.Site, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.sites {
		if item.ID == id {
			return cloneSite(item), nil
		}
	}
	return site.Site{}, ErrNotFound
}

func (s *Store) Create(item site.Site) (site.Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	normalized, err := normalizeSite(item)
	if err != nil {
		return site.Site{}, err
	}
	if err := s.ensureDomainUniquenessLocked(normalized, ""); err != nil {
		return site.Site{}, err
	}
	if err := s.ensureListenPortUniquenessLocked(normalized, ""); err != nil {
		return site.Site{}, err
	}
	item = cloneSite(normalized)
	item.CreatedAt = now
	item.UpdatedAt = now
	s.sites = append(s.sites, item)
	return cloneSite(item), s.saveLocked()
}

func (s *Store) Update(id string, patch site.Site) (site.Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalized, err := normalizeSite(patch)
	if err != nil {
		return site.Site{}, err
	}
	if err := s.ensureDomainUniquenessLocked(normalized, id); err != nil {
		return site.Site{}, err
	}
	if err := s.ensureListenPortUniquenessLocked(normalized, id); err != nil {
		return site.Site{}, err
	}
	normalized = cloneSite(normalized)
	for i, item := range s.sites {
		if item.ID != id {
			continue
		}
		item.Name = normalized.Name
		item.NodeID = normalized.NodeID
		item.Domain = normalized.Domain
		item.ListenPort = normalized.ListenPort
		item.AdditionalDomains = append([]string{}, normalized.AdditionalDomains...)
		item.CertificateID = normalized.CertificateID
		item.Upstream = normalized.Upstream
		item.Upstreams = append([]site.Upstream{}, normalized.Upstreams...)
		item.UpstreamTLS = normalized.UpstreamTLS
		item.LoadBalanceStrategy = normalized.LoadBalanceStrategy
		item.Routes = append([]site.RouteRule{}, normalized.Routes...)
		item.Resilience = normalized.Resilience
		item.Timeouts = normalized.Timeouts
		item.Cache = normalized.Cache
		item.Gzip = normalized.Gzip
		item.Brotli = normalized.Brotli
		item.Canary = normalized.Canary
		item.AutoRequestHeaders = normalized.AutoRequestHeaders
		item.AutoResponseHeaders = normalized.AutoResponseHeaders
		item.RequestHeaders = append([]site.Header{}, normalized.RequestHeaders...)
		item.ResponseHeaders = append([]site.Header{}, normalized.ResponseHeaders...)
		item.RemoveRequestHeaders = append([]string{}, normalized.RemoveRequestHeaders...)
		item.RemoveResponseHeaders = append([]string{}, normalized.RemoveResponseHeaders...)
		item.RateLimit = normalized.RateLimit
		item.TrafficControl = normalized.TrafficControl
		item.IPRuleSetIDs = append([]string{}, normalized.IPRuleSetIDs...)
		item.IPRuleSetID = normalized.IPRuleSetID
		item.IPAccess = normalized.IPAccess
		item.BasicAuth = normalized.BasicAuth
		item.Security = normalized.Security
		item.Enabled = normalized.Enabled
		item.ForceHTTPS = normalized.ForceHTTPS
		item.UpdatedAt = time.Now().UTC()
		s.sites[i] = item
		return cloneSite(item), s.saveLocked()
	}
	return site.Site{}, ErrNotFound
}

func (s *Store) SetEnabled(id string, enabled bool) (site.Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, item := range s.sites {
		if item.ID != id {
			continue
		}
		if enabled {
			test := item
			test.Enabled = true
			if err := s.ensureListenPortUniquenessLocked(test, id); err != nil {
				return site.Site{}, err
			}
		}
		item.Enabled = enabled
		item.UpdatedAt = time.Now().UTC()
		s.sites[i] = item
		return cloneSite(item), s.saveLocked()
	}
	return site.Site{}, ErrNotFound
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.sites)
	s.sites = slices.DeleteFunc(s.sites, func(item site.Site) bool {
		return item.ID == id
	})
	if len(s.sites) == n {
		return ErrNotFound
	}
	return s.saveLocked()
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
	if err := json.Unmarshal(data, &s.sites); err != nil {
		return err
	}
	for i := range s.sites {
		normalized, err := normalizeSite(s.sites[i])
		if err != nil {
			return fmt.Errorf("site %s validation failed: %w", s.sites[i].ID, err)
		}
		if normalized.CreatedAt.IsZero() {
			normalized.CreatedAt = time.Now().UTC()
		}
		if normalized.UpdatedAt.IsZero() {
			normalized.UpdatedAt = normalized.CreatedAt
		}
		s.sites[i] = normalized
	}
	if err := s.ensureExistingEnabledListenPortUniquenessLocked(); err != nil {
		return err
	}
	return nil
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.sites, "", "  ")
	if err != nil {
		return err
	}
	return s.blob.Save(context.Background(), data)
}

func normalizeSite(item site.Site) (site.Site, error) {
	item.NodeID = node.NormalizeID(item.NodeID)
	item.Domain, item.AdditionalDomains = site.NormalizeDomains(item.Domain, item.AdditionalDomains)
	item.Upstream, item.Upstreams = site.NormalizeUpstreams(item.Upstream, item.Upstreams)
	item.CertificateID = strings.TrimSpace(item.CertificateID)
	if item.LoadBalanceStrategy == "" {
		item.LoadBalanceStrategy = site.LoadBalanceRound
	}
	item.Name = strings.TrimSpace(item.Name)
	item.RemoveRequestHeaders = normalizeHeaderList(item.RemoveRequestHeaders)
	item.RemoveResponseHeaders = normalizeHeaderList(item.RemoveResponseHeaders)
	item.IPRuleSetID = strings.TrimSpace(item.IPRuleSetID)
	item.IPAccess.AllowCIDRs = normalizeStringList(item.IPAccess.AllowCIDRs)
	item.IPAccess.DenyCIDRs = normalizeStringList(item.IPAccess.DenyCIDRs)
	item.IPAccess.AllowASNs = normalizeStringList(item.IPAccess.AllowASNs)
	item.IPAccess.DenyASNs = normalizeStringList(item.IPAccess.DenyASNs)
	item.IPAccess.DenyReputationCIDRs = normalizeStringList(item.IPAccess.DenyReputationCIDRs)
	item.TrafficControl.AllowedMethods = site.NormalizeHTTPMethods(item.TrafficControl.AllowedMethods)
	item.Security.BlockUserAgentPatterns = normalizeStringList(item.Security.BlockUserAgentPatterns)
	item.UpstreamTLS.ServerName = strings.TrimSpace(item.UpstreamTLS.ServerName)
	item.UpstreamTLS.RootCAFile = strings.TrimSpace(item.UpstreamTLS.RootCAFile)
	item.UpstreamTLS.RootCAPEM = strings.TrimSpace(item.UpstreamTLS.RootCAPEM)
	item.Resilience.ActiveHealthCheck.Path = strings.TrimSpace(item.Resilience.ActiveHealthCheck.Path)
	item.Resilience.Retry.RetryOnStatuses = site.NormalizeStatusCodes(item.Resilience.Retry.RetryOnStatuses)
	item.Canary.Header = httpHeaderCanonical(item.Canary.Header)
	item.Canary.HeaderValue = strings.TrimSpace(item.Canary.HeaderValue)
	item.Canary.Cookie = strings.TrimSpace(item.Canary.Cookie)
	item.Canary.CookieValue = strings.TrimSpace(item.Canary.CookieValue)
	item.Canary.Upstream, item.Canary.Upstreams = site.NormalizeUpstreams(item.Canary.Upstream, item.Canary.Upstreams)
	if item.Canary.LoadBalanceStrategy == "" {
		item.Canary.LoadBalanceStrategy = site.LoadBalanceRound
	}

	for i := range item.Routes {
		item.Routes[i].Path = strings.TrimSpace(item.Routes[i].Path)
		item.Routes[i].Match = strings.TrimSpace(item.Routes[i].Match)
		item.Routes[i].RewritePattern = strings.TrimSpace(item.Routes[i].RewritePattern)
		item.Routes[i].RewriteReplacement = strings.TrimSpace(item.Routes[i].RewriteReplacement)
		item.Routes[i].Upstream, item.Routes[i].Upstreams = site.NormalizeUpstreams(item.Routes[i].Upstream, item.Routes[i].Upstreams)
		if item.Routes[i].LoadBalanceStrategy == "" {
			item.Routes[i].LoadBalanceStrategy = item.LoadBalanceStrategy
		}
	}

	if err := site.Validate(item); err != nil {
		return site.Site{}, err
	}
	return item, nil
}

func cloneSite(in site.Site) site.Site {
	out := in
	out.AdditionalDomains = append([]string{}, in.AdditionalDomains...)
	out.Upstreams = append([]site.Upstream{}, in.Upstreams...)
	out.Routes = make([]site.RouteRule, 0, len(in.Routes))
	for _, route := range in.Routes {
		clonedRoute := route
		clonedRoute.Methods = append([]string{}, route.Methods...)
		clonedRoute.Upstreams = append([]site.Upstream{}, route.Upstreams...)
		out.Routes = append(out.Routes, clonedRoute)
	}
	out.RequestHeaders = append([]site.Header{}, in.RequestHeaders...)
	out.ResponseHeaders = append([]site.Header{}, in.ResponseHeaders...)
	out.RemoveRequestHeaders = append([]string{}, in.RemoveRequestHeaders...)
	out.RemoveResponseHeaders = append([]string{}, in.RemoveResponseHeaders...)
	out.IPRuleSetIDs = append([]string{}, in.IPRuleSetIDs...)
	out.Resilience.Retry.RetryOnStatuses = append([]int{}, in.Resilience.Retry.RetryOnStatuses...)
	out.Canary.Upstreams = append([]site.Upstream{}, in.Canary.Upstreams...)
	out.TrafficControl.AllowedMethods = append([]string{}, in.TrafficControl.AllowedMethods...)
	out.Security.BlockUserAgentPatterns = append([]string{}, in.Security.BlockUserAgentPatterns...)
	out.IPAccess.AllowCIDRs = append([]string{}, in.IPAccess.AllowCIDRs...)
	out.IPAccess.DenyCIDRs = append([]string{}, in.IPAccess.DenyCIDRs...)
	out.IPAccess.AllowASNs = append([]string{}, in.IPAccess.AllowASNs...)
	out.IPAccess.DenyASNs = append([]string{}, in.IPAccess.DenyASNs...)
	out.IPAccess.DenyReputationCIDRs = append([]string{}, in.IPAccess.DenyReputationCIDRs...)
	out.BasicAuth = in.BasicAuth
	return out
}

func normalizeStringList(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func normalizeHeaderList(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		trimmed := strings.TrimSpace(httpHeaderCanonical(item))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func httpHeaderCanonical(name string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(name)), "-")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, "-")
}

func (s *Store) ensureDomainUniquenessLocked(item site.Site, exceptID string) error {
	claimed := map[string]struct{}{}
	for _, domain := range site.AllDomains(item) {
		claimed[domain] = struct{}{}
	}
	for _, existing := range s.sites {
		if existing.ID == exceptID || existing.NodeID != item.NodeID {
			continue
		}
		for _, domain := range site.AllDomains(existing) {
			if _, ok := claimed[domain]; ok {
				return fmt.Errorf("domain already exists: %s", domain)
			}
		}
	}
	return nil
}

func (s *Store) ensureListenPortUniquenessLocked(item site.Site, exceptID string) error {
	if !item.Enabled || item.ListenPort <= 0 {
		return nil
	}
	for _, existing := range s.sites {
		if existing.ID == exceptID || !existing.Enabled || existing.NodeID != item.NodeID {
			continue
		}
		if existing.ListenPort == item.ListenPort {
			return fmt.Errorf("listen port already exists: %d", item.ListenPort)
		}
	}
	return nil
}

func (s *Store) ensureExistingEnabledListenPortUniquenessLocked() error {
	claimed := map[int]struct{}{}
	for _, existing := range s.sites {
		if !existing.Enabled || existing.ListenPort <= 0 {
			continue
		}
		if _, ok := claimed[existing.ListenPort]; ok {
			return fmt.Errorf("listen port already exists: %d", existing.ListenPort)
		}
		claimed[existing.ListenPort] = struct{}{}
	}
	return nil
}
