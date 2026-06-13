package certmgr

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
)

func TestManagerCreateSelfSignedAndDelete(t *testing.T) {
	tmp := t.TempDir()
	m, err := New(filepath.Join(tmp, "certificates.json"), filepath.Join(tmp, "certs"), Options{})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	item, err := m.Create(Certificate{
		Name:    "local",
		Type:    TypeSelfSigned,
		Domains: []string{"example.com", "api.example.com"},
		SelfSigned: SelfSignedConfig{
			KeyAlgorithm: "rsa",
			ValidDays:    30,
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if item.Status != StatusActive {
		t.Fatalf("status = %s, want active", item.Status)
	}
	if item.Material.CertFile == "" || item.Material.KeyFile == "" {
		t.Fatalf("expected generated cert/key paths")
	}
	if _, err := m.Get(item.ID); err != nil {
		t.Fatalf("get: %v", err)
	}
	if err := m.Delete(item.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := m.Get(item.ID); err == nil {
		t.Fatalf("expected not found after delete")
	}
}

func TestManagerCreateACMEWithAutoIssue(t *testing.T) {
	tmp := t.TempDir()
	leaf := testLeaf(t, "example.com")

	m, err := New(filepath.Join(tmp, "certificates.json"), filepath.Join(tmp, "certs"), Options{
		EnableAutoTLS: true,
		IssueACME: func(_ context.Context, _ string, _ ACMEConfig) (*x509.Certificate, error) {
			return leaf, nil
		},
		LoadACMECache: func(_ string) (*x509.Certificate, error) {
			return nil, x509.ErrUnsupportedAlgorithm
		},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer m.Close()

	item, err := m.Create(Certificate{
		Type:    TypeACME,
		Domains: []string{"example.com"},
		ACME: ACMEConfig{
			AutoIssue: true,
		},
	})
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	if item.Status != StatusActive {
		t.Fatalf("status = %s, want active", item.Status)
	}
	if item.NotAfter.IsZero() {
		t.Fatalf("expected notAfter to be set")
	}
}

func TestMatchTLSCertificate(t *testing.T) {
	tmp := t.TempDir()
	m, err := New(filepath.Join(tmp, "certificates.json"), filepath.Join(tmp, "certs"), Options{})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	item, err := m.Create(Certificate{
		Type:    TypeSelfSigned,
		Domains: []string{"*.example.com"},
		SelfSigned: SelfSignedConfig{
			KeyAlgorithm: "rsa",
			ValidDays:    7,
		},
	})
	if err != nil {
		t.Fatalf("create self-signed: %v", err)
	}
	if item.Status != StatusActive {
		t.Fatalf("status = %s, want active", item.Status)
	}

	if _, err := m.MatchTLSCertificate("api.example.com"); err != nil {
		t.Fatalf("match wildcard cert: %v", err)
	}
	if _, err := m.MatchTLSCertificate("deep.api.example.com"); err == nil {
		t.Fatalf("expected wildcard mismatch for multi-level label")
	}
}

func TestGetTLSCertificateByID(t *testing.T) {
	tmp := t.TempDir()
	m, err := New(filepath.Join(tmp, "certificates.json"), filepath.Join(tmp, "certs"), Options{})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	item, err := m.Create(Certificate{
		Type:    TypeSelfSigned,
		Domains: []string{"example.com"},
		SelfSigned: SelfSignedConfig{
			KeyAlgorithm: "rsa",
			ValidDays:    7,
		},
	})
	if err != nil {
		t.Fatalf("create self-signed: %v", err)
	}

	if _, err := m.GetTLSCertificateByID(item.ID); err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if _, err := m.GetTLSCertificateByID("missing"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestGetTLSCertificateByIDACME(t *testing.T) {
	tmp := t.TempDir()
	certDir := filepath.Join(tmp, "certs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatalf("mkdir cert dir: %v", err)
	}

	certPEM, keyPEM := testCertAndKeyPEM(t, "example.com", time.Now().UTC().Add(72*time.Hour))
	if err := os.WriteFile(filepath.Join(certDir, "example.com"), append(certPEM, keyPEM...), 0o600); err != nil {
		t.Fatalf("write acme cache: %v", err)
	}

	m, err := New(filepath.Join(tmp, "certificates.json"), certDir, Options{
		LoadACMECache: func(domain string) (*x509.Certificate, error) {
			return LoadACMECachedCertificate(certDir, domain)
		},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer m.Close()

	item, err := m.Create(Certificate{
		Type:    TypeACME,
		Domains: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}

	cert, err := m.GetTLSCertificateByID(item.ID)
	if err != nil {
		t.Fatalf("get acme cert by id: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatalf("expected acme tls certificate with leaf data")
	}
}

func TestManagerCloseIsIdempotent(t *testing.T) {
	tmp := t.TempDir()
	m, err := New(filepath.Join(tmp, "certificates.json"), filepath.Join(tmp, "certs"), Options{})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestDownloadMaterial(t *testing.T) {
	tmp := t.TempDir()
	m, err := New(filepath.Join(tmp, "certificates.json"), filepath.Join(tmp, "certs"), Options{})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	item, err := m.Create(Certificate{
		Type:    TypeSelfSigned,
		Domains: []string{"example.com"},
		SelfSigned: SelfSignedConfig{
			KeyAlgorithm: "rsa",
			ValidDays:    7,
		},
	})
	if err != nil {
		t.Fatalf("create self-signed: %v", err)
	}

	certData, certName, certType, err := m.DownloadMaterial(item.ID, "cert", "pem", "")
	if err != nil {
		t.Fatalf("download cert: %v", err)
	}
	if certType != "application/x-pem-file" {
		t.Fatalf("unexpected cert content type: %s", certType)
	}
	if !strings.HasSuffix(certName, ".crt") {
		t.Fatalf("unexpected cert filename: %s", certName)
	}
	if !strings.Contains(string(certData), "BEGIN CERTIFICATE") {
		t.Fatalf("unexpected cert content")
	}

	keyData, keyName, keyType, err := m.DownloadMaterial(item.ID, "key", "der", "")
	if err != nil {
		t.Fatalf("download key: %v", err)
	}
	if keyType != "application/octet-stream" {
		t.Fatalf("unexpected key content type: %s", keyType)
	}
	if !strings.HasSuffix(keyName, ".key.der") {
		t.Fatalf("unexpected key filename: %s", keyName)
	}
	if len(keyData) == 0 {
		t.Fatalf("unexpected key content")
	}

	pubData, pubName, _, err := m.DownloadMaterial(item.ID, "pubkey", "pem", "")
	if err != nil {
		t.Fatalf("download pubkey: %v", err)
	}
	if !strings.HasSuffix(pubName, ".pub.pem") {
		t.Fatalf("unexpected pubkey filename: %s", pubName)
	}
	if !strings.Contains(string(pubData), "BEGIN PUBLIC KEY") {
		t.Fatalf("unexpected pubkey content")
	}

	zipData, zipName, zipType, err := m.DownloadMaterial(item.ID, "bundle", "zip", "")
	if err != nil {
		t.Fatalf("download bundle: %v", err)
	}
	if zipType != "application/zip" {
		t.Fatalf("unexpected zip content type: %s", zipType)
	}
	if !strings.HasSuffix(zipName, "-bundle.zip") {
		t.Fatalf("unexpected zip filename: %s", zipName)
	}
	if _, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData))); err != nil {
		t.Fatalf("bundle is not a valid zip: %v", err)
	}

	p12Data, p12Name, p12Type, err := m.DownloadMaterial(item.ID, "bundle", "p12", "changeit")
	if err != nil {
		t.Fatalf("download p12: %v", err)
	}
	if p12Type != "application/x-pkcs12" {
		t.Fatalf("unexpected p12 content type: %s", p12Type)
	}
	if !strings.HasSuffix(p12Name, ".p12") {
		t.Fatalf("unexpected p12 filename: %s", p12Name)
	}
	if _, cert, err := pkcs12.Decode(p12Data, "changeit"); err != nil || cert == nil {
		t.Fatalf("invalid p12 payload, err=%v certNil=%v", err, cert == nil)
	}

	jksData, jksName, jksType, err := m.DownloadMaterial(item.ID, "bundle", "jks", "changeit")
	if err != nil {
		t.Fatalf("download jks: %v", err)
	}
	if jksType != "application/octet-stream" {
		t.Fatalf("unexpected jks content type: %s", jksType)
	}
	if !strings.HasSuffix(jksName, ".jks") {
		t.Fatalf("unexpected jks filename: %s", jksName)
	}
	jks := keystore.New()
	if err := jks.Load(bytes.NewReader(jksData), []byte("changeit")); err != nil {
		t.Fatalf("invalid jks payload: %v", err)
	}

	if _, _, _, err := m.DownloadMaterial(item.ID, "foo", "pem", ""); err == nil {
		t.Fatalf("expected invalid kind error")
	}
}

func testLeaf(t *testing.T, domain string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	now := time.Now().UTC()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: domain, Organization: []string{"FlowProxy Test"}},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return leaf
}

func testCertAndKeyPEM(t *testing.T, domain string, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	now := time.Now().UTC()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(420),
		Subject:      pkix.Name{CommonName: domain, Organization: []string{"FlowProxy Test"}},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func TestACMERenewDue(t *testing.T) {
	now := time.Now().UTC()
	item := Certificate{
		Type:     TypeACME,
		Status:   StatusActive,
		NotAfter: now.Add(20 * 24 * time.Hour),
		ACME: ACMEConfig{
			RenewBeforeDays: 30,
		},
	}
	if !acmeRenewDue(item, now) {
		t.Fatalf("expected renew due when cert is inside renew window")
	}

	item.NotAfter = now.Add(90 * 24 * time.Hour)
	if acmeRenewDue(item, now) {
		t.Fatalf("expected renew not due when cert is far from expiry")
	}
}
