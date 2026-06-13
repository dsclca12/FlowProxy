package certmgr

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	downloadAssetCert      = "cert"
	downloadAssetFullChain = "fullchain"
	downloadAssetChain     = "chain"
	downloadAssetKey       = "key"
	downloadAssetPublicKey = "pubkey"
	downloadAssetBundle    = "bundle"

	downloadFormatPEM = "pem"
	downloadFormatDER = "der"
	downloadFormatZIP = "zip"
	downloadFormatPFX = "pfx"
	downloadFormatP12 = "p12"
	downloadFormatJKS = "jks"
)

type downloadableBundle struct {
	certs    []*x509.Certificate
	keyPEM   []byte
	keyDER   []byte
	pubPEM   []byte
	pubDER   []byte
	certPEM  []byte
	chainPEM []byte
	fullPEM  []byte
}

func (m *Manager) DownloadMaterial(id, asset, format, password string) ([]byte, string, string, error) {
	item, err := m.getCertificateForDownload(id)
	if err != nil {
		return nil, "", "", err
	}
	targetAsset, err := normalizeDownloadAsset(asset)
	if err != nil {
		return nil, "", "", err
	}
	targetFormat, err := normalizeDownloadFormat(format, targetAsset)
	if err != nil {
		return nil, "", "", err
	}

	bundle, err := m.loadDownloadBundle(item)
	if err != nil {
		return nil, "", "", err
	}
	baseName := downloadBaseName(item)
	pass := normalizeDownloadPassword(password)

	switch targetFormat {
	case downloadFormatPFX, downloadFormatP12:
		return exportPKCS12(bundle, baseName, targetAsset, targetFormat, pass)
	case downloadFormatJKS:
		return exportJKS(bundle, baseName, targetAsset, pass)
	}

	switch targetAsset {
	case downloadAssetCert:
		return exportLeaf(bundle, baseName, targetFormat)
	case downloadAssetFullChain:
		return exportFullChain(bundle, baseName, targetFormat)
	case downloadAssetChain:
		return exportChain(bundle, baseName, targetFormat)
	case downloadAssetKey:
		return exportPrivateKey(bundle, baseName, targetFormat)
	case downloadAssetPublicKey:
		return exportPublicKey(bundle, baseName, targetFormat)
	case downloadAssetBundle:
		return exportBundle(bundle, baseName)
	default:
		return nil, "", "", fmt.Errorf("unsupported download asset: %s", targetAsset)
	}
}

func (m *Manager) getCertificateForDownload(id string) (Certificate, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Certificate{}, ErrNotFound
	}
	m.mu.Lock()
	m.refreshLocked()
	var found Certificate
	ok := false
	for i := range m.items {
		if m.items[i].ID != id {
			continue
		}
		found = m.items[i]
		ok = true
		break
	}
	m.mu.Unlock()
	if !ok {
		return Certificate{}, ErrNotFound
	}
	return found, nil
}

func normalizeDownloadAsset(asset string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(asset))
	switch v {
	case "", "cert", "certificate", "leaf":
		return downloadAssetCert, nil
	case "fullchain", "full_chain", "full":
		return downloadAssetFullChain, nil
	case "chain", "intermediate", "ca_chain":
		return downloadAssetChain, nil
	case "key", "private", "private_key":
		return downloadAssetKey, nil
	case "pubkey", "public", "public_key", "pub":
		return downloadAssetPublicKey, nil
	case "bundle", "all", "archive":
		return downloadAssetBundle, nil
	default:
		return "", fmt.Errorf("unsupported download asset: %s", asset)
	}
}

func normalizeDownloadFormat(format string, asset string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(format))
	if asset == downloadAssetBundle {
		if v == "" || v == "zip" || v == "pem" || v == "der" || v == "crt" || v == "cer" || v == "key" {
			return downloadFormatZIP, nil
		}
		if v == downloadFormatPFX || v == downloadFormatP12 || v == downloadFormatJKS {
			return v, nil
		}
		return "", fmt.Errorf("unsupported download format: %s", format)
	}
	if v == "" {
		return downloadFormatPEM, nil
	}
	switch v {
	case "pem", "crt", "key":
		return downloadFormatPEM, nil
	case "der", "cer":
		return downloadFormatDER, nil
	case "zip":
		return downloadFormatZIP, nil
	case downloadFormatPFX, downloadFormatP12, downloadFormatJKS:
		return v, nil
	default:
		return "", fmt.Errorf("unsupported download format: %s", format)
	}
}

func normalizeDownloadPassword(password string) string {
	pass := strings.TrimSpace(password)
	if pass == "" {
		return pkcs12.DefaultPassword
	}
	return pass
}

func (m *Manager) loadDownloadBundle(item Certificate) (*downloadableBundle, error) {
	switch item.Type {
	case TypeSelfSigned:
		return m.loadSelfSignedBundle(item)
	case TypeACME:
		return m.loadACMEBundle(item)
	default:
		return nil, ErrMaterialUnavailable
	}
}

func (m *Manager) loadSelfSignedBundle(item Certificate) (*downloadableBundle, error) {
	certPath := strings.TrimSpace(item.Material.CertFile)
	if certPath == "" || !m.isAllowedMaterialPath(certPath) {
		return nil, ErrMaterialUnavailable
	}
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	certs, err := parseCertificates(certData)
	if err != nil || len(certs) == 0 {
		return nil, ErrMaterialUnavailable
	}

	var keyDER []byte
	keyPath := strings.TrimSpace(item.Material.KeyFile)
	if keyPath != "" {
		if !m.isAllowedMaterialPath(keyPath) {
			return nil, ErrMaterialUnavailable
		}
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		parsedKey, err := parsePrivateKey(keyData)
		if err == nil && parsedKey != nil {
			keyDER, _ = x509.MarshalPKCS8PrivateKey(parsedKey)
		}
	}
	return buildBundle(certs, keyDER)
}

func (m *Manager) loadACMEBundle(item Certificate) (*downloadableBundle, error) {
	seen := map[string]struct{}{}
	bestLeaf := (*x509.Certificate)(nil)
	var bestBundle *downloadableBundle

	for _, domain := range item.Domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" || strings.HasPrefix(domain, "*.") {
			continue
		}
		for _, candidate := range []string{domain, domain + "+rsa"} {
			path := filepath.Join(m.cacheDir, candidate)
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			if !m.isAllowedMaterialPath(path) {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			certs, err := parseCertificates(data)
			if err != nil || len(certs) == 0 {
				continue
			}
			parsedKey, err := parsePrivateKey(data)
			if err != nil {
				parsedKey = nil
			}
			var keyDER []byte
			if parsedKey != nil {
				keyDER, _ = x509.MarshalPKCS8PrivateKey(parsedKey)
			}
			bundle, err := buildBundle(certs, keyDER)
			if err != nil {
				continue
			}
			if bestLeaf == nil || bundle.certs[0].NotAfter.After(bestLeaf.NotAfter) {
				bestLeaf = bundle.certs[0]
				bestBundle = bundle
			}
		}
	}
	if bestBundle == nil {
		return nil, ErrMaterialUnavailable
	}
	return bestBundle, nil
}

func buildBundle(certs []*x509.Certificate, keyDER []byte) (*downloadableBundle, error) {
	if len(certs) == 0 || certs[0] == nil {
		return nil, ErrMaterialUnavailable
	}
	pubDER, err := x509.MarshalPKIXPublicKey(certs[0].PublicKey)
	if err != nil {
		return nil, err
	}

	b := &downloadableBundle{
		certs:    certs,
		certPEM:  encodeCertsPEM(certs[:1]),
		fullPEM:  encodeCertsPEM(certs),
		chainPEM: encodeCertsPEM(certs[1:]),
		pubDER:   pubDER,
		pubPEM:   pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
	}
	if len(keyDER) > 0 {
		b.keyDER = keyDER
		b.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}
	return b, nil
}

func exportLeaf(bundle *downloadableBundle, baseName string, format string) ([]byte, string, string, error) {
	switch format {
	case downloadFormatPEM:
		return bundle.certPEM, baseName + ".crt", "application/x-pem-file", nil
	case downloadFormatDER:
		return bundle.certs[0].Raw, baseName + ".cer", "application/pkix-cert", nil
	case downloadFormatZIP:
		entries := map[string][]byte{
			baseName + ".crt": bundle.certPEM,
			baseName + ".cer": bundle.certs[0].Raw,
		}
		return buildZIP(entries, baseName+"-cert.zip")
	default:
		return nil, "", "", fmt.Errorf("unsupported download format: %s", format)
	}
}

func exportFullChain(bundle *downloadableBundle, baseName string, format string) ([]byte, string, string, error) {
	switch format {
	case downloadFormatPEM:
		return bundle.fullPEM, baseName + "-fullchain.pem", "application/x-pem-file", nil
	case downloadFormatDER:
		if len(bundle.certs) == 1 {
			return bundle.certs[0].Raw, baseName + "-fullchain.cer", "application/pkix-cert", nil
		}
		entries := map[string][]byte{}
		for i, cert := range bundle.certs {
			entries[fmt.Sprintf("%s-fullchain-%d.cer", baseName, i+1)] = cert.Raw
		}
		return buildZIP(entries, baseName+"-fullchain.zip")
	case downloadFormatZIP:
		entries := map[string][]byte{
			baseName + "-fullchain.pem": bundle.fullPEM,
		}
		for i, cert := range bundle.certs {
			entries[fmt.Sprintf("%s-fullchain-%d.cer", baseName, i+1)] = cert.Raw
		}
		return buildZIP(entries, baseName+"-fullchain.zip")
	default:
		return nil, "", "", fmt.Errorf("unsupported download format: %s", format)
	}
}

func exportChain(bundle *downloadableBundle, baseName string, format string) ([]byte, string, string, error) {
	if len(bundle.certs) <= 1 {
		return nil, "", "", ErrMaterialUnavailable
	}
	chain := bundle.certs[1:]
	switch format {
	case downloadFormatPEM:
		return bundle.chainPEM, baseName + "-chain.pem", "application/x-pem-file", nil
	case downloadFormatDER:
		if len(chain) == 1 {
			return chain[0].Raw, baseName + "-chain.cer", "application/pkix-cert", nil
		}
		entries := map[string][]byte{}
		for i, cert := range chain {
			entries[fmt.Sprintf("%s-chain-%d.cer", baseName, i+1)] = cert.Raw
		}
		return buildZIP(entries, baseName+"-chain.zip")
	case downloadFormatZIP:
		entries := map[string][]byte{
			baseName + "-chain.pem": bundle.chainPEM,
		}
		for i, cert := range chain {
			entries[fmt.Sprintf("%s-chain-%d.cer", baseName, i+1)] = cert.Raw
		}
		return buildZIP(entries, baseName+"-chain.zip")
	default:
		return nil, "", "", fmt.Errorf("unsupported download format: %s", format)
	}
}

func exportPrivateKey(bundle *downloadableBundle, baseName string, format string) ([]byte, string, string, error) {
	if len(bundle.keyDER) == 0 {
		return nil, "", "", ErrMaterialUnavailable
	}
	switch format {
	case downloadFormatPEM:
		return bundle.keyPEM, baseName + ".key", "application/x-pem-file", nil
	case downloadFormatDER:
		return bundle.keyDER, baseName + ".key.der", "application/octet-stream", nil
	case downloadFormatZIP:
		entries := map[string][]byte{
			baseName + ".key":     bundle.keyPEM,
			baseName + ".key.der": bundle.keyDER,
		}
		return buildZIP(entries, baseName+"-key.zip")
	default:
		return nil, "", "", fmt.Errorf("unsupported download format: %s", format)
	}
}

func exportPublicKey(bundle *downloadableBundle, baseName string, format string) ([]byte, string, string, error) {
	switch format {
	case downloadFormatPEM:
		return bundle.pubPEM, baseName + ".pub.pem", "application/x-pem-file", nil
	case downloadFormatDER:
		return bundle.pubDER, baseName + ".pub.der", "application/octet-stream", nil
	case downloadFormatZIP:
		entries := map[string][]byte{
			baseName + ".pub.pem": bundle.pubPEM,
			baseName + ".pub.der": bundle.pubDER,
		}
		return buildZIP(entries, baseName+"-pubkey.zip")
	default:
		return nil, "", "", fmt.Errorf("unsupported download format: %s", format)
	}
}

func exportBundle(bundle *downloadableBundle, baseName string) ([]byte, string, string, error) {
	entries := map[string][]byte{
		baseName + ".crt":           bundle.certPEM,
		baseName + ".cer":           bundle.certs[0].Raw,
		baseName + "-fullchain.pem": bundle.fullPEM,
		baseName + ".pub.pem":       bundle.pubPEM,
		baseName + ".pub.der":       bundle.pubDER,
	}
	if len(bundle.certs) > 1 {
		entries[baseName+"-chain.pem"] = bundle.chainPEM
		for i, cert := range bundle.certs[1:] {
			entries[fmt.Sprintf("%s-chain-%d.cer", baseName, i+1)] = cert.Raw
		}
	}
	if len(bundle.keyDER) > 0 {
		entries[baseName+".key"] = bundle.keyPEM
		entries[baseName+".key.der"] = bundle.keyDER
	}
	return buildZIP(entries, baseName+"-bundle.zip")
}

func exportPKCS12(bundle *downloadableBundle, baseName string, asset string, format string, password string) ([]byte, string, string, error) {
	if asset == downloadAssetPublicKey {
		return nil, "", "", fmt.Errorf("format %s is not supported for asset %s", format, asset)
	}
	certs, err := certificatesForAsset(bundle, asset)
	if err != nil {
		return nil, "", "", err
	}
	ext := ".pfx"
	if format == downloadFormatP12 {
		ext = ".p12"
	}

	if len(bundle.keyDER) > 0 && asset != downloadAssetChain {
		privateKey, err := parsePrivateKeyDER(bundle.keyDER)
		if err != nil {
			return nil, "", "", err
		}
		leaf := certs[0]
		var caCerts []*x509.Certificate
		if len(certs) > 1 {
			caCerts = certs[1:]
		}
		data, err := pkcs12.Modern.Encode(privateKey, leaf, caCerts, password)
		if err != nil {
			return nil, "", "", err
		}
		return data, baseName + ext, "application/x-pkcs12", nil
	}

	data, err := pkcs12.Modern.EncodeTrustStore(certs, password)
	if err != nil {
		return nil, "", "", err
	}
	return data, baseName + ext, "application/x-pkcs12", nil
}

func exportJKS(bundle *downloadableBundle, baseName string, asset string, password string) ([]byte, string, string, error) {
	if asset == downloadAssetPublicKey {
		return nil, "", "", fmt.Errorf("format %s is not supported for asset %s", downloadFormatJKS, asset)
	}
	certs, err := certificatesForAsset(bundle, asset)
	if err != nil {
		return nil, "", "", err
	}

	store := keystore.New()
	storePassword := []byte(password)
	now := time.Now()

	// Prefer a private key entry when key material exists and current asset is not chain-only.
	if len(bundle.keyDER) > 0 && asset != downloadAssetChain {
		chain := make([]keystore.Certificate, 0, len(certs))
		for _, cert := range certs {
			if cert == nil {
				continue
			}
			chain = append(chain, keystore.Certificate{
				Type:    "X509",
				Content: cert.Raw,
			})
		}
		if len(chain) > 0 {
			if err := store.SetPrivateKeyEntry(baseName, keystore.PrivateKeyEntry{
				CreationTime:     now,
				PrivateKey:       bundle.keyDER,
				CertificateChain: chain,
			}, storePassword); err != nil {
				return nil, "", "", err
			}
		}
	}

	if len(store.Aliases()) == 0 {
		for idx, cert := range certs {
			if cert == nil {
				continue
			}
			alias := fmt.Sprintf("%s-cert-%d", baseName, idx+1)
			if idx == 0 {
				alias = baseName
			}
			store.SetTrustedCertificateEntry(alias, keystore.TrustedCertificateEntry{
				CreationTime: now,
				Certificate: keystore.Certificate{
					Type:    "X509",
					Content: cert.Raw,
				},
			})
		}
	}

	var buf bytes.Buffer
	if err := store.Store(&buf, storePassword); err != nil {
		return nil, "", "", err
	}
	return buf.Bytes(), baseName + ".jks", "application/octet-stream", nil
}

func certificatesForAsset(bundle *downloadableBundle, asset string) ([]*x509.Certificate, error) {
	switch asset {
	case downloadAssetCert, downloadAssetPublicKey:
		if len(bundle.certs) == 0 || bundle.certs[0] == nil {
			return nil, ErrMaterialUnavailable
		}
		return []*x509.Certificate{bundle.certs[0]}, nil
	case downloadAssetFullChain, downloadAssetKey, downloadAssetBundle:
		if len(bundle.certs) == 0 {
			return nil, ErrMaterialUnavailable
		}
		return bundle.certs, nil
	case downloadAssetChain:
		if len(bundle.certs) <= 1 {
			return nil, ErrMaterialUnavailable
		}
		return bundle.certs[1:], nil
	default:
		return nil, fmt.Errorf("unsupported download asset: %s", asset)
	}
}

func buildZIP(entries map[string][]byte, zipName string) ([]byte, string, string, error) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	keys := make([]string, 0, len(entries))
	for name := range entries {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		payload := entries[name]
		if len(payload) == 0 {
			continue
		}
		file, err := writer.Create(name)
		if err != nil {
			_ = writer.Close()
			return nil, "", "", err
		}
		if _, err := file.Write(payload); err != nil {
			_ = writer.Close()
			return nil, "", "", err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", "", err
	}
	return buf.Bytes(), zipName, "application/zip", nil
}

func (m *Manager) isAllowedMaterialPath(path string) bool {
	candidate := filepath.Clean(strings.TrimSpace(path))
	if candidate == "" || candidate == "." {
		return false
	}
	return isPathWithin(candidate, m.certDir) || isPathWithin(candidate, m.cacheDir)
}

func isPathWithin(candidate string, root string) bool {
	root = filepath.Clean(strings.TrimSpace(root))
	candidate = filepath.Clean(strings.TrimSpace(candidate))
	if root == "" || root == "." || candidate == "" || candidate == "." {
		return false
	}
	if candidate == root {
		return true
	}
	return strings.HasPrefix(candidate, root+string(os.PathSeparator))
}

func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	blocks := decodePEMBlocks(data)
	certs := make([]*x509.Certificate, 0, len(blocks))
	for _, block := range blocks {
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	if len(certs) > 0 {
		return certs, nil
	}
	if cert, err := x509.ParseCertificate(data); err == nil {
		return []*x509.Certificate{cert}, nil
	}
	return nil, errors.New("no certificate data found")
}

func parsePrivateKey(data []byte) (crypto.PrivateKey, error) {
	blocks := decodePEMBlocks(data)
	for _, block := range blocks {
		key, err := parsePrivateKeyDER(block.Bytes)
		if err == nil {
			return key, nil
		}
	}
	return parsePrivateKeyDER(data)
}

func parsePrivateKeyDER(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("failed to parse private key")
}

func decodePEMBlocks(data []byte) []*pem.Block {
	out := make([]*pem.Block, 0)
	rest := data
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		out = append(out, block)
		rest = next
	}
	return out
}

func encodeCertsPEM(certs []*x509.Certificate) []byte {
	if len(certs) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	return buf.Bytes()
}

func downloadBaseName(item Certificate) string {
	base := sanitizeFileName(item.Name)
	if base == "" && len(item.Domains) > 0 {
		base = sanitizeFileName(item.Domains[0])
	}
	if base == "" {
		base = item.ID
	}
	if base == "" {
		base = "certificate"
	}
	return base
}
