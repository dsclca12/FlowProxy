package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"flowproxy/internal/certmgr"
	"flowproxy/internal/config"
)

// resolveAdminHTTPSAddr resolves interface binding for admin HTTPS address.
func resolveAdminHTTPSAddr(raw string) string {
	addr, err := normalizeBindAddr(raw, 9443)
	if err != nil {
		return raw
	}
	return addr
}

func validateAdminTLSConfig(cfg config.Config) error {
	addr := strings.TrimSpace(cfg.AdminHTTPSAddr)
	if addr == "" {
		return nil
	}
	certificateID := strings.TrimSpace(cfg.AdminTLSCertificateID)
	certFile := strings.TrimSpace(cfg.AdminTLSCertFile)
	keyFile := strings.TrimSpace(cfg.AdminTLSKeyFile)
	if (certFile == "") != (keyFile == "") {
		return fmt.Errorf("ADMIN_TLS_CERT_FILE and ADMIN_TLS_KEY_FILE must be set together")
	}
	if certificateID != "" && (certFile != "" || keyFile != "") {
		return fmt.Errorf("ADMIN_TLS_CERTIFICATE_ID cannot be used together with ADMIN_TLS_CERT_FILE/ADMIN_TLS_KEY_FILE")
	}
	if certificateID == "" && certFile == "" && keyFile == "" && !cfg.AdminTLSAutoSelfSigned {
		return fmt.Errorf("admin https is enabled but no managed cert id / cert key pair configured and auto self-signed is disabled")
	}
	return nil
}

type adminTLSRedirectPolicy struct {
	mu        sync.RWMutex
	enabled   bool
	httpsAddr string
}

func newAdminTLSRedirectPolicy() *adminTLSRedirectPolicy {
	return &adminTLSRedirectPolicy{}
}

func (p *adminTLSRedirectPolicy) Apply(cfg config.Config) {
	p.mu.Lock()
	p.enabled = strings.TrimSpace(cfg.AdminHTTPSAddr) != "" && cfg.AdminTLSRedirectHTTP
	p.httpsAddr = strings.TrimSpace(cfg.AdminHTTPSAddr)
	p.mu.Unlock()
}

func (p *adminTLSRedirectPolicy) Middleware(next http.Handler) http.Handler {
	if p == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		p.mu.RLock()
		enabled := p.enabled
		httpsAddr := p.httpsAddr
		p.mu.RUnlock()
		if !enabled {
			next.ServeHTTP(w, req)
			return
		}
		httpsPort := listenerPort(httpsAddr)
		targetHost := redirectHost(req.Host, httpsPort)
		target := "https://" + targetHost + req.URL.RequestURI()
		http.Redirect(w, req, target, http.StatusMovedPermanently)
	})
}

type adminTLSServerManager struct {
	mu           sync.Mutex
	handler      http.Handler
	certMgr      *certmgr.Manager
	readTimeout  time.Duration
	writeTimeout time.Duration

	server   *http.Server
	addr     string
	snapshot adminTLSSnapshot
}

type adminTLSSnapshot struct {
	enabled        bool
	addr           string
	certFile       string
	keyFile        string
	certificateID  string
	autoSelfSigned bool
}

func newAdminTLSServerManager(handler http.Handler, certMgr *certmgr.Manager) *adminTLSServerManager {
	return &adminTLSServerManager{
		handler:      handler,
		certMgr:      certMgr,
		readTimeout:  10 * time.Second,
		writeTimeout: 30 * time.Second,
	}
}

func (m *adminTLSServerManager) Apply(cfg config.Config) error {
	httpsAddr := resolveAdminHTTPSAddr(cfg.AdminHTTPSAddr)
	snapshot := adminTLSSnapshot{
		enabled:        strings.TrimSpace(httpsAddr) != "",
		addr:           strings.TrimSpace(httpsAddr),
		certFile:       strings.TrimSpace(cfg.AdminTLSCertFile),
		keyFile:        strings.TrimSpace(cfg.AdminTLSKeyFile),
		certificateID:  strings.TrimSpace(cfg.AdminTLSCertificateID),
		autoSelfSigned: cfg.AdminTLSAutoSelfSigned,
	}

	if !snapshot.enabled {
		m.mu.Lock()
		oldServer := m.server
		oldAddr := m.addr
		m.server = nil
		m.addr = ""
		m.snapshot = snapshot
		m.mu.Unlock()
		if oldServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = oldServer.Shutdown(ctx)
			cancel()
			log.Printf("admin HTTPS listener stopped on %s", oldAddr)
		}
		return nil
	}

	m.mu.Lock()
	same := m.server != nil && m.snapshot == snapshot
	m.mu.Unlock()
	if same {
		return nil
	}

	tlsCfg, err := buildAdminTLSConfig(cfg, m.certMgr)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", snapshot.addr)
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(listener, tlsCfg)
	server := &http.Server{
		Addr:         snapshot.addr,
		Handler:      m.handler,
		ReadTimeout:  m.readTimeout,
		WriteTimeout: m.writeTimeout,
		TLSConfig:    tlsCfg,
	}

	m.mu.Lock()
	oldServer := m.server
	oldAddr := m.addr
	m.server = server
	m.addr = snapshot.addr
	m.snapshot = snapshot
	m.mu.Unlock()

	log.Printf("admin HTTPS listening on %s", snapshot.addr)
	go func(target string, srv *http.Server, ln net.Listener) {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("admin https server failed on %s: %v", target, err)
		}
	}(snapshot.addr, server, tlsListener)

	if oldServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := oldServer.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
			log.Printf("admin https server shutdown failed on %s: %v", oldAddr, err)
		}
		cancel()
	}
	return nil
}

func (m *adminTLSServerManager) Shutdown(ctx context.Context) {
	if m == nil {
		return
	}
	m.mu.Lock()
	server := m.server
	addr := m.addr
	m.server = nil
	m.addr = ""
	m.snapshot = adminTLSSnapshot{}
	m.mu.Unlock()
	if server == nil {
		return
	}
	if err := server.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
		log.Printf("admin https server shutdown failed on %s: %v", addr, err)
	}
}

func buildAdminTLSConfig(cfg config.Config, certMgr *certmgr.Manager) (*tls.Config, error) {
	certificateID := strings.TrimSpace(cfg.AdminTLSCertificateID)
	if certificateID != "" {
		if certMgr == nil {
			return nil, fmt.Errorf("certificate manager is unavailable for ADMIN_TLS_CERTIFICATE_ID")
		}
		if _, err := certMgr.GetTLSCertificateByID(certificateID); err != nil {
			return nil, fmt.Errorf("load ADMIN_TLS_CERTIFICATE_ID %s failed: %w", certificateID, err)
		}
		id := certificateID
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return certMgr.GetTLSCertificateByID(id)
			},
		}, nil
	}

	certFile := strings.TrimSpace(cfg.AdminTLSCertFile)
	keyFile := strings.TrimSpace(cfg.AdminTLSKeyFile)
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}

	cert, err := generateSelfSignedAdminTLSCert(adminTLSHosts(cfg.AdminHTTPSAddr))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func adminTLSHosts(addr string) []string {
	value := strings.TrimSpace(addr)
	if value == "" {
		return []string{"localhost", "127.0.0.1", "::1"}
	}
	host := ""
	if strings.HasPrefix(value, ":") {
		host = ""
	} else if _, err := strconv.Atoi(value); err == nil {
		host = ""
	} else {
		parsedHost, _, err := net.SplitHostPort(value)
		if err == nil {
			host = strings.Trim(parsedHost, "[]")
		}
	}
	out := []string{"localhost", "127.0.0.1", "::1"}
	if host != "" && host != "0.0.0.0" && host != "::" {
		out = append(out, host)
	}
	return dedupeStrings(out)
}

func dedupeStrings(items []string) []string {
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

func generateSelfSignedAdminTLSCert(hosts []string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	notBefore := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "FlowProxy Admin",
			Organization: []string{"FlowProxy"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, host)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return tls.X509KeyPair(certPEM, keyPEM)
}
