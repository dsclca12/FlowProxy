package certmgr

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type MirroredCertificate struct {
	Certificate Certificate
	BundleZIP   []byte
}

func (m *Manager) ReplaceMirrored(items []MirroredCertificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mirrorRoot := filepath.Join(m.cacheDir, "synced")
	if err := os.RemoveAll(mirrorRoot); err != nil {
		return err
	}
	if err := os.MkdirAll(mirrorRoot, 0o700); err != nil {
		return err
	}

	now := time.Now().UTC()
	out := make([]Certificate, 0, len(items))
	for idx, item := range items {
		normalized, err := normalizeCertificate(item.Certificate)
		if err != nil {
			return fmt.Errorf("item[%d] normalize failed: %w", idx, err)
		}
		if strings.TrimSpace(normalized.ID) == "" {
			return fmt.Errorf("item[%d] id is required", idx)
		}
		if normalized.CreatedAt.IsZero() {
			normalized.CreatedAt = now
		}
		if normalized.UpdatedAt.IsZero() {
			normalized.UpdatedAt = now
		}
		normalized.CreatedAt = normalized.CreatedAt.UTC()
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
		normalized.Material = CertificateAssets{}

		if len(item.BundleZIP) > 0 {
			subDir := filepath.Join(mirrorRoot, sanitizeFileName(normalized.ID))
			if strings.TrimSpace(filepath.Base(subDir)) == "" || filepath.Base(subDir) == "." {
				return fmt.Errorf("invalid mirrored certificate id: %s", normalized.ID)
			}
			if err := os.MkdirAll(subDir, 0o700); err != nil {
				return err
			}
			certPEM, keyPEM, err := parseMirrorBundle(item.BundleZIP)
			if err != nil {
				return fmt.Errorf("certificate %s bundle parse failed: %w", normalized.ID, err)
			}
			certPath := filepath.Join(subDir, normalized.ID+".crt")
			if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
				return err
			}
			normalized.Material.CertFile = certPath
			if len(keyPEM) > 0 {
				keyPath := filepath.Join(subDir, normalized.ID+".key")
				if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
					return err
				}
				normalized.Material.KeyFile = keyPath
			}
			if leaf, err := loadCertificateFromPEMBytes(certPEM); err == nil && leaf != nil {
				normalized.NotBefore = leaf.NotBefore
				normalized.NotAfter = leaf.NotAfter
				normalized.Serial = strings.ToUpper(leaf.SerialNumber.Text(16))
				normalized.Issuer = strings.Join(leaf.Issuer.Organization, ",")
				if normalized.Issuer == "" {
					normalized.Issuer = leaf.Issuer.CommonName
				}
				if normalized.Status == "" {
					normalized.Status = StatusActive
				}
			}
		}
		out = append(out, normalized)
	}

	m.items = out
	return m.saveLocked()
}

func parseMirrorBundle(bundleZIP []byte) ([]byte, []byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(bundleZIP), int64(len(bundleZIP)))
	if err != nil {
		return nil, nil, err
	}
	var certPEM []byte
	certScore := 0
	var keyPEM []byte
	keyScore := 0
	for _, file := range reader.File {
		name := strings.ToLower(strings.TrimSpace(file.Name))
		if name == "" {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return nil, nil, err
		}
		data, readErr := func() ([]byte, error) {
			defer rc.Close()
			return io.ReadAll(rc)
		}()
		if readErr != nil {
			return nil, nil, readErr
		}
		if candidate, ok := maybeCertificatePEM(data); ok {
			score := 1
			if strings.Contains(name, "fullchain") {
				score = 3
			} else if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".pem") {
				score = 2
			}
			if score >= certScore {
				certScore = score
				certPEM = candidate
			}
		}
		if candidate, ok := maybePrivateKeyPEM(data); ok {
			score := 1
			if strings.HasSuffix(name, ".key") || strings.HasSuffix(name, ".pem") {
				score = 2
			}
			if score >= keyScore {
				keyScore = score
				keyPEM = candidate
			}
		}
	}
	if len(certPEM) == 0 {
		return nil, nil, fmt.Errorf("bundle does not contain certificate material")
	}
	return certPEM, keyPEM, nil
}

func maybeCertificatePEM(data []byte) ([]byte, bool) {
	certs, err := parseCertificates(data)
	if err != nil || len(certs) == 0 {
		return nil, false
	}
	out := encodeCertsPEM(certs)
	return out, len(out) > 0
}

func maybePrivateKeyPEM(data []byte) ([]byte, bool) {
	key, err := parsePrivateKey(data)
	if err != nil || key == nil {
		return nil, false
	}
	out, err := privateKeyToPEM(key)
	if err != nil || len(out) == 0 {
		return nil, false
	}
	return out, true
}

func privateKeyToPEM(key crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
