package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"flowproxy/internal/certmgr"
	"flowproxy/internal/config"
	"flowproxy/internal/proxy"
)

const (
	zeroSSLDirectoryURL    = "https://acme.zerossl.com/v2/DV90"
	defaultACMERenewBefore = 30 * 24 * time.Hour
	defaultACMERenewDays   = 30
	defaultACMEProvider    = "letsencrypt"
	defaultACMEChallenge   = "http-01"
	defaultACMECertKeyType = "ecdsa"
	customACMEProvider     = "custom"
	zeroSSLACMEProvider    = "zerossl"
)

type acmeProfile struct {
	email       string
	directory   string
	renewBefore time.Duration
	keyType     string
}

type acmeManagerPool struct {
	mu           sync.RWMutex
	cacheDir     string
	defaultEmail string
	runtime      *autocert.Manager
	issueByKey   map[string]*autocert.Manager
}

func newACMEManagerPool(cfg config.Config, router *proxy.Router) *acmeManagerPool {
	runtimeProfile := acmeProfile{
		email:       strings.TrimSpace(cfg.LetsEncryptEmail),
		directory:   acme.LetsEncryptURL,
		renewBefore: defaultACMERenewBefore,
		keyType:     defaultACMECertKeyType,
	}
	return &acmeManagerPool{
		cacheDir:     cfg.CertDir,
		defaultEmail: strings.TrimSpace(cfg.LetsEncryptEmail),
		runtime: newAutoCertManager(
			cfg.CertDir,
			runtimeProfile,
			func(_ context.Context, host string) error {
				normalized := normalizeACMEHost(host)
				for _, domain := range router.Domains() {
					if domain == normalized {
						return nil
					}
				}
				return errors.New("host not configured")
			},
		),
		issueByKey: map[string]*autocert.Manager{},
	}
}

func (p *acmeManagerPool) RuntimeManager() *autocert.Manager {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.runtime
}

func (p *acmeManagerPool) Issue(_ context.Context, domain string, cfg certmgr.ACMEConfig) (*x509.Certificate, error) {
	if p == nil {
		return nil, errors.New("acme manager pool is nil")
	}
	host := normalizeACMEHost(domain)
	if host == "" {
		return nil, errors.New("domain is required")
	}

	profile, err := normalizeACMEProfile(cfg, p.defaultEmail)
	if err != nil {
		return nil, err
	}

	manager := p.issueManager(host, profile)
	hello := &tls.ClientHelloInfo{
		ServerName:        host,
		SupportedProtos:   []string{"h2", "http/1.1"},
		SignatureSchemes:  acmeSignatureSchemes(profile.keyType),
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
	}
	cert, err := manager.GetCertificate(hello)
	if err != nil {
		return nil, err
	}
	return certmgr.ToTLSLeaf(cert)
}

func (p *acmeManagerPool) HTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		handler := fallback
		managers := p.snapshotManagers()
		for i := len(managers) - 1; i >= 0; i-- {
			handler = managers[i].HTTPHandler(handler)
		}
		handler.ServeHTTP(w, req)
	})
}

func (p *acmeManagerPool) issueManager(domain string, profile acmeProfile) *autocert.Manager {
	key := issueManagerKey(domain, profile)

	p.mu.RLock()
	if mgr, ok := p.issueByKey[key]; ok {
		p.mu.RUnlock()
		return mgr
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	if mgr, ok := p.issueByKey[key]; ok {
		return mgr
	}
	mgr := newAutoCertManager(
		p.cacheDir,
		profile,
		autocert.HostWhitelist(domain),
	)
	p.issueByKey[key] = mgr
	return mgr
}

func (p *acmeManagerPool) snapshotManagers() []*autocert.Manager {
	if p == nil {
		return nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.issueByKey) == 0 {
		if p.runtime == nil {
			return nil
		}
		return []*autocert.Manager{p.runtime}
	}

	keys := make([]string, 0, len(p.issueByKey))
	for key := range p.issueByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]*autocert.Manager, 0, len(keys)+1)
	if p.runtime != nil {
		out = append(out, p.runtime)
	}
	for _, key := range keys {
		if mgr := p.issueByKey[key]; mgr != nil {
			out = append(out, mgr)
		}
	}
	return out
}

func newAutoCertManager(cacheDir string, profile acmeProfile, hostPolicy autocert.HostPolicy) *autocert.Manager {
	manager := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Cache:       autocert.DirCache(cacheDir),
		HostPolicy:  hostPolicy,
		RenewBefore: profile.renewBefore,
		Email:       profile.email,
	}
	if profile.directory != "" {
		manager.Client = &acme.Client{DirectoryURL: profile.directory}
	}
	return manager
}

func normalizeACMEProfile(cfg certmgr.ACMEConfig, fallbackEmail string) (acmeProfile, error) {
	email := strings.TrimSpace(cfg.Email)
	if email == "" {
		email = strings.TrimSpace(fallbackEmail)
	}

	keyType := strings.ToLower(strings.TrimSpace(cfg.KeyType))
	if keyType == "" {
		keyType = defaultACMECertKeyType
	}
	if keyType != "ecdsa" && keyType != "rsa" {
		return acmeProfile{}, fmt.Errorf("unsupported acme keyType: %s", cfg.KeyType)
	}

	renewDays := cfg.RenewBeforeDays
	if renewDays <= 0 {
		renewDays = defaultACMERenewDays
	}
	if renewDays > 365 {
		return acmeProfile{}, fmt.Errorf("renewBeforeDays must be <= 365")
	}

	challenge := strings.ToLower(strings.TrimSpace(cfg.Challenge))
	if challenge == "" {
		challenge = defaultACMEChallenge
	}
	if challenge != "http-01" && challenge != "dns-01" {
		return acmeProfile{}, fmt.Errorf("unsupported challenge type: %s (supported: http-01, dns-01)", challenge)
	}

	directoryURL, err := resolveACMEDirectoryURL(
		strings.ToLower(strings.TrimSpace(cfg.Provider)),
		strings.TrimSpace(cfg.DirectoryURL),
	)
	if err != nil {
		return acmeProfile{}, err
	}

	return acmeProfile{
		email:       email,
		directory:   directoryURL,
		renewBefore: time.Duration(renewDays) * 24 * time.Hour,
		keyType:     keyType,
	}, nil
}

func resolveACMEDirectoryURL(provider string, rawDirectory string) (string, error) {
	directory := strings.TrimSpace(rawDirectory)
	if directory != "" {
		if err := validateACMEDirectoryURL(directory); err != nil {
			return "", err
		}
		return directory, nil
	}

	switch provider {
	case "", defaultACMEProvider:
		return acme.LetsEncryptURL, nil
	case zeroSSLACMEProvider:
		return zeroSSLDirectoryURL, nil
	case customACMEProvider:
		return "", errors.New("directoryUrl is required when provider=custom")
	default:
		return "", fmt.Errorf("unsupported acme provider: %s", provider)
	}
}

func validateACMEDirectoryURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return errors.New("invalid directoryUrl")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("directoryUrl must use http or https")
	}
	if u.Host == "" {
		return errors.New("directoryUrl host is required")
	}
	return nil
}

func normalizeACMEHost(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimSuffix(host, ".")
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}
	return host
}

func issueManagerKey(domain string, profile acmeProfile) string {
	return strings.Join([]string{
		normalizeACMEHost(domain),
		strings.ToLower(strings.TrimSpace(profile.email)),
		strings.ToLower(strings.TrimSpace(profile.directory)),
		strconvDurationSeconds(profile.renewBefore),
		profile.keyType,
	}, "|")
}

func strconvDurationSeconds(value time.Duration) string {
	return fmt.Sprintf("%d", int64(value/time.Second))
}

func acmeSignatureSchemes(keyType string) []tls.SignatureScheme {
	switch keyType {
	case "rsa":
		return []tls.SignatureScheme{
			tls.PSSWithSHA512,
			tls.PSSWithSHA384,
			tls.PSSWithSHA256,
			tls.PKCS1WithSHA512,
			tls.PKCS1WithSHA384,
			tls.PKCS1WithSHA256,
		}
	default:
		return []tls.SignatureScheme{
			tls.ECDSAWithP521AndSHA512,
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP256AndSHA256,
		}
	}
}
