package certmgr

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (m *Manager) issueSelfSignedLocked(item *Certificate) error {
	if err := os.MkdirAll(m.certDir, 0o700); err != nil {
		return err
	}

	cfg := item.SelfSigned
	notBefore := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := notBefore.Add(time.Duration(cfg.ValidDays) * 24 * time.Hour)
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	dnsNames := normalizeStringList(append(append([]string{}, item.Domains...), cfg.DNSNames...))
	ipAddresses, err := parseIPs(cfg.IPAddresses)
	if err != nil {
		return err
	}
	uriValues, err := parseURIs(cfg.URIs)
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subjectFromConfig(cfg, item.Domains[0]),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		EmailAddresses:        append([]string{}, cfg.EmailAddresses...),
		URIs:                  uriValues,
		BasicConstraintsValid: true,
		IsCA:                  cfg.IsCA,
	}

	if cfg.IsCA {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.MaxPathLen = cfg.MaxPathLen
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	privKey, pubKey, keyPEM, err := generatePrivateKeyPEM(cfg)
	if err != nil {
		return err
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	certPath := filepath.Join(m.certDir, item.ID+".crt")
	keyPath := filepath.Join(m.certDir, item.ID+".key")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("failed to write private key file: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	item.Material = CertificateAssets{CertFile: certPath, KeyFile: keyPath}
	item.Status = StatusActive
	item.LastError = ""
	item.Issuer = strings.Join(leaf.Issuer.Organization, ",")
	if item.Issuer == "" {
		item.Issuer = leaf.Issuer.CommonName
	}
	item.Serial = strings.ToUpper(leaf.SerialNumber.Text(16))
	item.NotBefore = leaf.NotBefore
	item.NotAfter = leaf.NotAfter
	return nil
}

func generatePrivateKeyPEM(cfg SelfSignedConfig) (any, any, []byte, error) {
	switch cfg.KeyAlgorithm {
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, cfg.RSABits)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		return key, &key.PublicKey, pemBytes, nil
	case "ecdsa":
		curve := elliptic.P256()
		switch cfg.ECDSACurve {
		case "p384":
			curve = elliptic.P384()
		case "p521":
			curve = elliptic.P521()
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to marshal ECDSA key: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		return key, &key.PublicKey, pemBytes, nil
	case "ed25519":
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to marshal ed25519 key: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		return key, pub, pemBytes, nil
	default:
		return nil, nil, nil, fmt.Errorf("unsupported key algorithm: %s", cfg.KeyAlgorithm)
	}
}
