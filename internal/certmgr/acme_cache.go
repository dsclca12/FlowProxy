package certmgr

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

func LoadACMECachedCertificate(certDir, domain string) (*x509.Certificate, error) {
	candidates := []string{domain, domain + "+rsa"}
	var best *x509.Certificate
	for _, name := range candidates {
		leaf, err := loadCertificateFromPEMFile(filepath.Join(certDir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			continue
		}
		if best == nil || leaf.NotAfter.After(best.NotAfter) {
			best = leaf
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no cached certificate for domain %s", domain)
	}
	return best, nil
}
