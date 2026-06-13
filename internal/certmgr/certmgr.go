package certmgr

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"flowproxy/internal/persist"
)

const (
	TypeACME       = "acme"
	TypeSelfSigned = "self_signed"

	StatusPending = "pending"
	StatusActive  = "active"
	StatusError   = "error"

	defaultSelfSignedDays = 397
	defaultACMERenewDays  = 30
	maxACMERenewDays      = 365
	autoRenewCheckEvery   = 10 * time.Minute
	autoRenewRetryAfter   = 15 * time.Minute
)

type Certificate struct {
	ID         string            `json:"id"`
	Name       string            `json:"name,omitempty"`
	Type       string            `json:"type"`
	Domains    []string          `json:"domains"`
	Status     string            `json:"status"`
	LastError  string            `json:"lastError,omitempty"`
	Issuer     string            `json:"issuer,omitempty"`
	Serial     string            `json:"serial,omitempty"`
	NotBefore  time.Time         `json:"notBefore,omitempty"`
	NotAfter   time.Time         `json:"notAfter,omitempty"`
	CreatedAt  time.Time         `json:"createdAt"`
	UpdatedAt  time.Time         `json:"updatedAt"`
	ACME       ACMEConfig        `json:"acme,omitempty"`
	SelfSigned SelfSignedConfig  `json:"selfSigned,omitempty"`
	Material   CertificateAssets `json:"material,omitempty"`
}

type ACMEConfig struct {
	Email           string            `json:"email,omitempty"`
	Provider        string            `json:"provider,omitempty"`
	DirectoryURL    string            `json:"directoryUrl,omitempty"`
	Challenge       string            `json:"challenge,omitempty"`
	KeyType         string            `json:"keyType,omitempty"`
	PreferredChain  string            `json:"preferredChain,omitempty"`
	RenewBeforeDays int               `json:"renewBeforeDays,omitempty"`
	AutoIssue       bool              `json:"autoIssue,omitempty"`
	DNSProvider     DNSProviderConfig `json:"dnsProvider,omitempty"`
}

type SelfSignedConfig struct {
	CommonName         string   `json:"commonName,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
	Country            []string `json:"country,omitempty"`
	Province           []string `json:"province,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	StreetAddress      []string `json:"streetAddress,omitempty"`
	PostalCode         []string `json:"postalCode,omitempty"`
	DNSNames           []string `json:"dnsNames,omitempty"`
	IPAddresses        []string `json:"ipAddresses,omitempty"`
	EmailAddresses     []string `json:"emailAddresses,omitempty"`
	URIs               []string `json:"uris,omitempty"`
	ValidDays          int      `json:"validDays,omitempty"`
	KeyAlgorithm       string   `json:"keyAlgorithm,omitempty"`
	RSABits            int      `json:"rsaBits,omitempty"`
	ECDSACurve         string   `json:"ecdsaCurve,omitempty"`
	IsCA               bool     `json:"isCA,omitempty"`
	MaxPathLen         int      `json:"maxPathLen,omitempty"`
}

type CertificateAssets struct {
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
}

type Options struct {
	EnableAutoTLS bool
	IssueACME     func(ctx context.Context, domain string, cfg ACMEConfig) (*x509.Certificate, error)
	LoadACMECache func(domain string) (*x509.Certificate, error)
}

type Manager struct {
	mu       sync.RWMutex
	blob     persist.BlobStore
	cacheDir string
	certDir  string
	options  Options
	items    []Certificate

	lastAutoRenew map[string]time.Time
	stopAutoRenew chan struct{}
	autoRenewDone chan struct{}
	closeOnce     sync.Once
}

type persistModel struct {
	Certificates []Certificate `json:"certificates"`
}

var ErrNotFound = errors.New("certificate not found")
var ErrMaterialUnavailable = errors.New("certificate material is not available")

func New(filePath, certDir string, options Options) (*Manager, error) {
	return NewWithBlob(persist.NewFileBlobStore(filePath), certDir, options)
}

func NewWithBlob(blob persist.BlobStore, certDir string, options Options) (*Manager, error) {
	if blob == nil {
		return nil, fmt.Errorf("certificate blob backend is required")
	}
	m := &Manager{
		blob:          blob,
		cacheDir:      filepath.Clean(certDir),
		certDir:       filepath.Join(certDir, "managed"),
		options:       options,
		items:         []Certificate{},
		lastAutoRenew: map[string]time.Time{},
		stopAutoRenew: make(chan struct{}),
		autoRenewDone: make(chan struct{}),
	}
	if err := m.load(); err != nil {
		return nil, err
	}
	m.startAutoRenewLoop()
	return m, nil
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		close(m.stopAutoRenew)
		<-m.autoRenewDone
	})
	return nil
}

func (m *Manager) List() []Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshLocked()
	out := make([]Certificate, len(m.items))
	copy(out, m.items)
	return out
}

func (m *Manager) Get(id string) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.items {
		if m.items[i].ID != id {
			continue
		}
		m.refreshItemLocked(&m.items[i])
		return m.items[i], nil
	}
	return Certificate{}, ErrNotFound
}

func (m *Manager) Create(input Certificate) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized, err := normalizeCertificate(input)
	if err != nil {
		return Certificate{}, err
	}

	now := time.Now().UTC()
	if normalized.ID == "" {
		normalized.ID = newID()
	}
	normalized.CreatedAt = now
	normalized.UpdatedAt = now
	if normalized.Status == "" {
		normalized.Status = StatusPending
	}

	if normalized.Type == TypeSelfSigned {
		if err := m.issueSelfSignedLocked(&normalized); err != nil {
			normalized.Status = StatusError
			normalized.LastError = err.Error()
		}
	}

	if normalized.Type == TypeACME && normalized.ACME.AutoIssue {
		m.issueACMELocked(&normalized)
	}

	m.items = append(m.items, normalized)
	if err := m.saveLocked(); err != nil {
		return Certificate{}, err
	}
	return normalized, nil
}

func (m *Manager) Issue(id string) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.items {
		if m.items[i].ID != id {
			continue
		}
		item := &m.items[i]
		item.UpdatedAt = time.Now().UTC()
		item.LastError = ""

		switch item.Type {
		case TypeSelfSigned:
			if err := m.issueSelfSignedLocked(item); err != nil {
				item.Status = StatusError
				item.LastError = err.Error()
			} else {
				item.Status = StatusActive
			}
		case TypeACME:
			m.issueACMELocked(item)
		default:
			item.Status = StatusError
			item.LastError = "unsupported certificate type"
		}
		if err := m.saveLocked(); err != nil {
			return Certificate{}, err
		}
		return *item, nil
	}
	return Certificate{}, ErrNotFound
}

func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	index := -1
	for i, item := range m.items {
		if item.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return ErrNotFound
	}

	item := m.items[index]
	if item.Type == TypeSelfSigned {
		if item.Material.CertFile != "" {
			_ = os.Remove(item.Material.CertFile)
		}
		if item.Material.KeyFile != "" {
			_ = os.Remove(item.Material.KeyFile)
		}
	}
	m.items = slices.Delete(m.items, index, index+1)
	return m.saveLocked()
}

func (m *Manager) ReplaceAll(items []Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	out := make([]Certificate, 0, len(items))
	seen := map[string]struct{}{}
	for i, item := range items {
		normalized, err := normalizeCertificate(item)
		if err != nil {
			return fmt.Errorf("certificate[%d] validation failed: %w", i, err)
		}
		if normalized.ID == "" {
			normalized.ID = newID()
		}
		if _, ok := seen[normalized.ID]; ok {
			return fmt.Errorf("duplicate certificate id: %s", normalized.ID)
		}
		seen[normalized.ID] = struct{}{}
		if normalized.CreatedAt.IsZero() {
			normalized.CreatedAt = now
		}
		if normalized.UpdatedAt.IsZero() {
			normalized.UpdatedAt = normalized.CreatedAt
		}
		normalized.CreatedAt = normalized.CreatedAt.UTC()
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
		out = append(out, normalized)
	}
	m.items = out
	m.refreshLocked()
	return m.saveLocked()
}

func normalizeCertificate(input Certificate) (Certificate, error) {
	item := input
	item.Name = strings.TrimSpace(item.Name)
	item.Type = strings.TrimSpace(item.Type)
	if item.Type == "" {
		item.Type = TypeSelfSigned
	}

	domains, err := normalizeDomains(item.Domains)
	if err != nil {
		return Certificate{}, err
	}
	item.Domains = domains

	switch item.Type {
	case TypeACME:
		item.ACME = normalizeACME(item.ACME)
		item.SelfSigned = SelfSignedConfig{}
	case TypeSelfSigned:
		cfg, err := normalizeSelfSigned(item.SelfSigned, item.Domains)
		if err != nil {
			return Certificate{}, err
		}
		item.SelfSigned = cfg
		item.ACME = ACMEConfig{}
	default:
		return Certificate{}, fmt.Errorf("unsupported certificate type: %s", item.Type)
	}
	return item, nil
}

func normalizeACME(cfg ACMEConfig) ACMEConfig {
	cfg.Email = strings.TrimSpace(cfg.Email)
	cfg.Provider = strings.TrimSpace(strings.ToLower(cfg.Provider))
	if cfg.Provider == "" {
		cfg.Provider = "letsencrypt"
	}
	switch cfg.Provider {
	case "letsencrypt", "zerossl", "custom":
	default:
		cfg.Provider = "letsencrypt"
	}
	cfg.DirectoryURL = strings.TrimSpace(cfg.DirectoryURL)
	cfg.Challenge = strings.TrimSpace(strings.ToLower(cfg.Challenge))
	if cfg.Challenge == "" {
		cfg.Challenge = "http-01"
	}
	cfg.KeyType = strings.TrimSpace(strings.ToLower(cfg.KeyType))
	if cfg.KeyType == "" {
		cfg.KeyType = "ecdsa"
	}
	if cfg.KeyType != "ecdsa" && cfg.KeyType != "rsa" {
		cfg.KeyType = "ecdsa"
	}
	cfg.PreferredChain = strings.TrimSpace(cfg.PreferredChain)
	if cfg.RenewBeforeDays <= 0 {
		cfg.RenewBeforeDays = defaultACMERenewDays
	}
	if cfg.RenewBeforeDays > maxACMERenewDays {
		cfg.RenewBeforeDays = maxACMERenewDays
	}
	return cfg
}

func normalizeSelfSigned(cfg SelfSignedConfig, certDomains []string) (SelfSignedConfig, error) {
	cfg.CommonName = strings.TrimSpace(cfg.CommonName)
	cfg.Organization = normalizeStringList(cfg.Organization)
	cfg.OrganizationalUnit = normalizeStringList(cfg.OrganizationalUnit)
	cfg.Country = normalizeStringList(cfg.Country)
	cfg.Province = normalizeStringList(cfg.Province)
	cfg.Locality = normalizeStringList(cfg.Locality)
	cfg.StreetAddress = normalizeStringList(cfg.StreetAddress)
	cfg.PostalCode = normalizeStringList(cfg.PostalCode)
	cfg.DNSNames = normalizeStringList(cfg.DNSNames)
	cfg.IPAddresses = normalizeStringList(cfg.IPAddresses)
	cfg.EmailAddresses = normalizeStringList(cfg.EmailAddresses)
	cfg.URIs = normalizeStringList(cfg.URIs)

	if cfg.ValidDays <= 0 {
		cfg.ValidDays = defaultSelfSignedDays
	}
	if cfg.ValidDays > 36500 {
		return SelfSignedConfig{}, errors.New("validDays must be <= 36500")
	}

	cfg.KeyAlgorithm = strings.TrimSpace(strings.ToLower(cfg.KeyAlgorithm))
	if cfg.KeyAlgorithm == "" {
		cfg.KeyAlgorithm = "rsa"
	}

	switch cfg.KeyAlgorithm {
	case "rsa":
		if cfg.RSABits == 0 {
			cfg.RSABits = 2048
		}
		if cfg.RSABits < 2048 || cfg.RSABits > 8192 {
			return SelfSignedConfig{}, errors.New("rsaBits must be in [2048, 8192]")
		}
	case "ecdsa":
		cfg.ECDSACurve = strings.TrimSpace(strings.ToLower(cfg.ECDSACurve))
		if cfg.ECDSACurve == "" {
			cfg.ECDSACurve = "p256"
		}
		if cfg.ECDSACurve != "p256" && cfg.ECDSACurve != "p384" && cfg.ECDSACurve != "p521" {
			return SelfSignedConfig{}, errors.New("ecdsaCurve must be one of p256/p384/p521")
		}
	case "ed25519":
		cfg.RSABits = 0
		cfg.ECDSACurve = ""
	default:
		return SelfSignedConfig{}, errors.New("keyAlgorithm must be rsa/ecdsa/ed25519")
	}

	if cfg.CommonName == "" {
		cfg.CommonName = certDomains[0]
	}
	if cfg.MaxPathLen < 0 {
		cfg.MaxPathLen = 0
	}
	return cfg, nil
}

func (m *Manager) load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := m.blob.Load(context.Background())
	if err != nil {
		if persist.IsNotFound(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}

	var model persistModel
	if err := json.Unmarshal(data, &model); err == nil && model.Certificates != nil {
		m.items = model.Certificates
	} else {
		var legacy []Certificate
		if err := json.Unmarshal(data, &legacy); err != nil {
			return err
		}
		m.items = legacy
	}

	for i := range m.items {
		normalized, err := normalizeCertificate(m.items[i])
		if err != nil {
			return fmt.Errorf("certificate %s validation failed: %w", m.items[i].ID, err)
		}
		if normalized.ID == "" {
			normalized.ID = newID()
		}
		if normalized.CreatedAt.IsZero() {
			normalized.CreatedAt = time.Now().UTC()
		}
		if normalized.UpdatedAt.IsZero() {
			normalized.UpdatedAt = normalized.CreatedAt
		}
		m.items[i] = normalized
	}
	m.refreshLocked()
	return nil
}

func (m *Manager) saveLocked() error {
	model := persistModel{Certificates: m.items}
	data, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		return err
	}
	return m.blob.Save(context.Background(), data)
}

func (m *Manager) refreshLocked() {
	now := time.Now().UTC()
	for i := range m.items {
		m.refreshItemLocked(&m.items[i])
		if !m.items[i].NotAfter.IsZero() && m.items[i].NotAfter.Before(now) {
			if m.items[i].Status == StatusActive {
				m.items[i].Status = StatusError
				if m.items[i].LastError == "" {
					m.items[i].LastError = "certificate expired"
				}
			}
		}
	}
}

func (m *Manager) refreshItemLocked(item *Certificate) {
	if item.Type != TypeACME || m.options.LoadACMECache == nil {
		return
	}

	best := (*x509.Certificate)(nil)
	for _, domain := range item.Domains {
		if strings.HasPrefix(domain, "*.") {
			continue
		}
		leaf, err := m.options.LoadACMECache(domain)
		if err != nil || leaf == nil {
			continue
		}
		if best == nil || leaf.NotAfter.Before(best.NotAfter) {
			best = leaf
		}
	}

	if best == nil {
		if item.Status == "" {
			item.Status = StatusPending
		}
		return
	}

	item.Status = StatusActive
	item.LastError = ""
	item.Issuer = strings.Join(best.Issuer.Organization, ",")
	item.Serial = strings.ToUpper(best.SerialNumber.Text(16))
	item.NotBefore = best.NotBefore
	item.NotAfter = best.NotAfter
}

func (m *Manager) issueACMELocked(item *Certificate) {
	if !m.options.EnableAutoTLS {
		item.Status = StatusError
		item.LastError = "auto tls is disabled"
		return
	}

	challenge := strings.ToLower(strings.TrimSpace(item.ACME.Challenge))
	if challenge == "" {
		challenge = "http-01"
	}

	item.Status = StatusPending
	item.LastError = ""

	if challenge == "dns-01" {
		m.issueACMELockedDNS(item)
		return
	}

	// HTTP-01 flow (existing)
	if m.options.IssueACME == nil {
		item.Status = StatusError
		item.LastError = "acme issuer not configured"
		return
	}

	var firstErr error
	var best *x509.Certificate
	for _, domain := range item.Domains {
		if strings.HasPrefix(domain, "*.") {
			if firstErr == nil {
				firstErr = errors.New("wildcard domain requires dns-01; current challenge uses http-01")
			}
			continue
		}
		leaf, err := m.options.IssueACME(context.Background(), domain, item.ACME)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", domain, err)
			}
			continue
		}
		if leaf != nil && selectPreferredLeaf(leaf, best, item.ACME.PreferredChain) {
			best = leaf
		}
	}

	if best != nil {
		item.Status = StatusActive
		item.Issuer = strings.Join(best.Issuer.Organization, ",")
		item.Serial = strings.ToUpper(best.SerialNumber.Text(16))
		item.NotBefore = best.NotBefore
		item.NotAfter = best.NotAfter
	}
	if firstErr != nil {
		item.Status = StatusError
		item.LastError = firstErr.Error()
	}
}

func (m *Manager) issueACMELockedDNS(item *Certificate) {
	email := strings.TrimSpace(item.ACME.Email)
	dnsCfg := item.ACME.DNSProvider
	keyType := strings.TrimSpace(item.ACME.KeyType)
	if keyType == "" {
		keyType = "ecdsa"
	}

	directoryURL := strings.TrimSpace(item.ACME.DirectoryURL)
	if directoryURL == "" {
		switch strings.ToLower(strings.TrimSpace(item.ACME.Provider)) {
		case "", "letsencrypt":
			directoryURL = "https://acme-v02.api.letsencrypt.org/directory"
		case "zerossl":
			directoryURL = "https://acme.zerossl.com/v2/DV90"
		}
	}

	domains := make([]string, len(item.Domains))
	for i, d := range item.Domains {
		domains[i] = strings.TrimSpace(d)
	}

	leaf, keyPEM, certPEM, err := issueACMEDNS(domains, email, dnsCfg, keyType, directoryURL)
	if err != nil {
		item.Status = StatusError
		item.LastError = fmt.Sprintf("dns-01 issue failed: %v", err)
		return
	}

	// Save cert and key to managed cert directory
	if err := os.MkdirAll(m.certDir, 0o755); err != nil {
		item.Status = StatusError
		item.LastError = fmt.Sprintf("create cert dir: %v", err)
		return
	}

	certPath := filepath.Join(m.certDir, item.ID+".crt")
	keyPath := filepath.Join(m.certDir, item.ID+".key")

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		item.Status = StatusError
		item.LastError = fmt.Sprintf("write cert file: %v", err)
		return
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		item.Status = StatusError
		item.LastError = fmt.Sprintf("write key file: %v", err)
		_ = os.Remove(certPath)
		return
	}

	item.Material.CertFile = certPath
	item.Material.KeyFile = keyPath
	item.Status = StatusActive
	item.LastError = ""
	item.Issuer = strings.Join(leaf.Issuer.Organization, ",")
	item.Serial = strings.ToUpper(leaf.SerialNumber.Text(16))
	item.NotBefore = leaf.NotBefore
	item.NotAfter = leaf.NotAfter
}

func selectPreferredLeaf(candidate *x509.Certificate, current *x509.Certificate, preferredChain string) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	needle := strings.ToLower(strings.TrimSpace(preferredChain))
	if needle != "" {
		candidateMatch := strings.Contains(strings.ToLower(candidate.Issuer.String()), needle)
		currentMatch := strings.Contains(strings.ToLower(current.Issuer.String()), needle)
		if candidateMatch != currentMatch {
			return candidateMatch
		}
	}
	return candidate.NotAfter.Before(current.NotAfter)
}

func (m *Manager) startAutoRenewLoop() {
	if m.options.IssueACME == nil {
		close(m.autoRenewDone)
		return
	}
	go func() {
		defer close(m.autoRenewDone)
		ticker := time.NewTicker(autoRenewCheckEvery)
		defer ticker.Stop()

		m.autoRenewDue()
		for {
			select {
			case <-ticker.C:
				m.autoRenewDue()
			case <-m.stopAutoRenew:
				return
			}
		}
	}()
}

func (m *Manager) autoRenewDue() {
	now := time.Now().UTC()
	changed := false

	m.mu.Lock()
	for i := range m.items {
		item := &m.items[i]
		if item.Type != TypeACME {
			continue
		}
		m.refreshItemLocked(item)
		if !acmeRenewDue(*item, now) {
			continue
		}
		if last, ok := m.lastAutoRenew[item.ID]; ok && now.Sub(last) < autoRenewRetryAfter {
			continue
		}
		m.lastAutoRenew[item.ID] = now
		item.UpdatedAt = now
		m.issueACMELocked(item)
		changed = true
	}
	if changed {
		_ = m.saveLocked()
	}
	m.mu.Unlock()
}

func acmeRenewDue(item Certificate, now time.Time) bool {
	if item.Type != TypeACME {
		return false
	}
	renewDays := item.ACME.RenewBeforeDays
	if renewDays <= 0 {
		renewDays = defaultACMERenewDays
	}
	if renewDays > maxACMERenewDays {
		renewDays = maxACMERenewDays
	}
	if item.NotAfter.IsZero() {
		return item.Status == StatusPending || item.Status == StatusError
	}
	renewBeforeAt := item.NotAfter.Add(-time.Duration(renewDays) * 24 * time.Hour)
	return !now.Before(renewBeforeAt)
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func normalizeDomains(domains []string) ([]string, error) {
	out := make([]string, 0, len(domains))
	seen := map[string]struct{}{}
	for _, raw := range domains {
		domain := strings.ToLower(strings.TrimSpace(raw))
		domain = strings.TrimPrefix(domain, "http://")
		domain = strings.TrimPrefix(domain, "https://")
		if idx := strings.Index(domain, ":"); idx > 0 {
			domain = domain[:idx]
		}
		domain = strings.TrimSuffix(domain, ".")
		if domain == "" {
			continue
		}
		if strings.HasPrefix(domain, "*.") {
			if strings.Count(domain, "*") > 1 {
				return nil, fmt.Errorf("invalid wildcard domain: %s", domain)
			}
			if len(domain) <= 2 {
				return nil, fmt.Errorf("invalid domain: %s", domain)
			}
		} else if net.ParseIP(domain) == nil {
			parts := strings.Split(domain, ".")
			if len(parts) < 2 {
				return nil, fmt.Errorf("invalid domain: %s", domain)
			}
			for _, p := range parts {
				if p == "" {
					return nil, fmt.Errorf("invalid domain: %s", domain)
				}
			}
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	if len(out) == 0 {
		return nil, errors.New("at least one domain is required")
	}
	slices.Sort(out)
	return out, nil
}

func normalizeStringList(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		v := strings.TrimSpace(item)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func loadCertificateFromPEMFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return loadCertificateFromPEMBytes(data)
}

func loadCertificateFromPEMBytes(data []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		return leaf, nil
	}
	return nil, errors.New("no certificate block found")
}

func parseIPs(items []string) ([]net.IP, error) {
	out := make([]net.IP, 0, len(items))
	for _, item := range items {
		ip := net.ParseIP(strings.TrimSpace(item))
		if ip == nil {
			return nil, fmt.Errorf("invalid IP SAN: %s", item)
		}
		out = append(out, ip)
	}
	return out, nil
}

func parseURIs(items []string) ([]*url.URL, error) {
	out := make([]*url.URL, 0, len(items))
	for _, item := range items {
		u, err := url.Parse(strings.TrimSpace(item))
		if err != nil || u.Scheme == "" {
			return nil, fmt.Errorf("invalid URI SAN: %s", item)
		}
		out = append(out, u)
	}
	return out, nil
}

func subjectFromConfig(cfg SelfSignedConfig, defaultCN string) pkix.Name {
	subject := pkix.Name{CommonName: cfg.CommonName}
	if subject.CommonName == "" {
		subject.CommonName = defaultCN
	}
	subject.Organization = append([]string{}, cfg.Organization...)
	subject.OrganizationalUnit = append([]string{}, cfg.OrganizationalUnit...)
	subject.Country = append([]string{}, cfg.Country...)
	subject.Province = append([]string{}, cfg.Province...)
	subject.Locality = append([]string{}, cfg.Locality...)
	subject.StreetAddress = append([]string{}, cfg.StreetAddress...)
	subject.PostalCode = append([]string{}, cfg.PostalCode...)
	return subject
}

func ToTLSLeaf(cert *tls.Certificate) (*x509.Certificate, error) {
	if cert == nil {
		return nil, errors.New("certificate is nil")
	}
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("no leaf certificate")
	}
	return x509.ParseCertificate(cert.Certificate[0])
}

func (m *Manager) MatchTLSCertificate(serverName string) (*tls.Certificate, error) {
	host := strings.ToLower(strings.TrimSpace(serverName))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil, ErrNotFound
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshLocked()

	match := m.findSelfSignedMatchLocked(host)
	if match == nil {
		return nil, ErrNotFound
	}

	return loadSelfSignedTLSCertificate(*match)
}

func (m *Manager) GetTLSCertificateByID(id string) (*tls.Certificate, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrNotFound
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshLocked()

	for i := range m.items {
		item := m.items[i]
		if item.ID != id {
			continue
		}
		if item.Status != StatusActive {
			return nil, fmt.Errorf("certificate %s is not active", id)
		}
		switch item.Type {
		case TypeSelfSigned:
			if strings.TrimSpace(item.Material.CertFile) == "" || strings.TrimSpace(item.Material.KeyFile) == "" {
				return nil, fmt.Errorf("certificate %s has no key pair", id)
			}
			return loadSelfSignedTLSCertificate(item)
		case TypeACME:
			return m.loadACMETLSCertificate(item)
		default:
			return nil, fmt.Errorf("certificate %s does not contain local key material", id)
		}
	}
	return nil, ErrNotFound
}

func sanitizeFileName(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, ch := range value {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch == '-' || ch == '_' || ch == '.':
			b.WriteRune(ch)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if out == "" {
		return ""
	}
	return out
}

func loadSelfSignedTLSCertificate(item Certificate) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(item.Material.CertFile, item.Material.KeyFile)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	return &cert, nil
}

func (m *Manager) loadACMETLSCertificate(item Certificate) (*tls.Certificate, error) {
	bundle, err := m.loadACMEBundle(item)
	if err != nil {
		if errors.Is(err, ErrMaterialUnavailable) {
			return nil, fmt.Errorf("certificate %s does not contain local key material", item.ID)
		}
		return nil, err
	}
	if len(bundle.keyPEM) == 0 {
		return nil, fmt.Errorf("certificate %s has no key pair", item.ID)
	}
	cert, err := tls.X509KeyPair(bundle.fullPEM, bundle.keyPEM)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	return &cert, nil
}

func (m *Manager) findSelfSignedMatchLocked(host string) *Certificate {
	var exact *Certificate
	var wildcard *Certificate
	bestWildcardSuffix := -1

	for i := range m.items {
		item := &m.items[i]
		if item.Type != TypeSelfSigned || item.Status != StatusActive {
			continue
		}
		if item.Material.CertFile == "" || item.Material.KeyFile == "" {
			continue
		}
		for _, domain := range item.Domains {
			d := strings.ToLower(strings.TrimSpace(domain))
			if d == "" {
				continue
			}
			if d == host {
				exact = item
				break
			}
			if !strings.HasPrefix(d, "*.") {
				continue
			}
			suffix := strings.TrimPrefix(d, "*.")
			if !strings.HasSuffix(host, "."+suffix) {
				continue
			}
			labelPrefix := strings.TrimSuffix(host, "."+suffix)
			if labelPrefix == "" || strings.Contains(labelPrefix, ".") {
				continue
			}
			if len(suffix) > bestWildcardSuffix {
				bestWildcardSuffix = len(suffix)
				wildcard = item
			}
		}
		if exact != nil {
			break
		}
	}
	if exact != nil {
		return exact
	}
	return wildcard
}
