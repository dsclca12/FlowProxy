package certmgr

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// DNSProviderConfig holds credentials for a DNS provider used in DNS-01 challenges.
type DNSProviderConfig struct {
	// Provider name, e.g. "cloudflare", "alidns", "manual"
	Name string `json:"name,omitempty"`

	// Provider-specific credentials as a JSON object.
	// For Cloudflare: {"authToken": "..."}
	// For AliDNS: {"accessKeyId": "...", "accessKeySecret": "..."}
	// For manual/print: {} (prints TXT record to log)
	Config json.RawMessage `json:"config,omitempty"`
}

// dnsChallengeSolver handles DNS-01 TXT record operations for a given provider.
type dnsChallengeSolver interface {
	SetTXTRecord(ctx context.Context, domain, value string) error
	ClearTXTRecord(ctx context.Context, domain, value string) error
}

// issueACMEDNS obtains a certificate via DNS-01 challenge using golang.org/x/crypto/acme.
// It supports wildcard domains and multiple DNS providers.
// Returns the leaf certificate, PEM-encoded private key, and PEM-encoded certificate chain.
func issueACMEDNS(domains []string, email string, dnsCfg DNSProviderConfig, keyType string, directoryURL string) (leaf *x509.Certificate, keyPEM []byte, certPEM []byte, err error) {
	if len(domains) == 0 {
		return nil, nil, nil, errors.New("at least one domain is required")
	}
	if strings.TrimSpace(dnsCfg.Name) == "" {
		return nil, nil, nil, errors.New("dns provider name is required for dns-01 challenge")
	}

	// Generate account key (must implement crypto.Signer for acme.Client.Key)
	accountKey, err := generateSigner(keyType)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate account key: %w", err)
	}

	// Generate certificate private key
	certKey, err := generateSigner(keyType)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate cert key: %w", err)
	}

	certKeyDER, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal cert key: %w", err)
	}

	// Create ACME client
	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: directoryURL,
		UserAgent:    "FlowProxy/1.0",
	}

	// Register account if email is provided
	if strings.TrimSpace(email) != "" {
		acct := &acme.Account{Contact: []string{"mailto:" + strings.TrimSpace(email)}}
		if _, err := client.Register(context.Background(), acct, acme.AcceptTOS); err != nil {
			// If already registered, ignore conflict errors
		}
	}

	// Create DNS challenge solver
	solver, err := newDNSSolver(dnsCfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create dns solver: %w", err)
	}

	// Build authorization identifiers
	ids := make([]acme.AuthzID, len(domains))
	for i, d := range domains {
		ids[i] = acme.AuthzID{Type: "dns", Value: strings.TrimSpace(d)}
	}

	// Order certificate
	var allAuthzURLs []string
	for _, id := range ids {
		auth, err := client.Authorize(context.Background(), id.Value)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("authorize %s: %w", id.Value, err)
		}
		allAuthzURLs = append(allAuthzURLs, auth.URI)
	}

	for _, authURL := range allAuthzURLs {
		auth, err := client.GetAuthorization(context.Background(), authURL)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("get authorization: %w", err)
		}

		// Find DNS-01 challenge
		var dnsChallenge *acme.Challenge
		for _, ch := range auth.Challenges {
			if ch.Type == "dns-01" {
				dnsChallenge = ch
				break
			}
		}
		if dnsChallenge == nil {
			return nil, nil, nil, fmt.Errorf("no dns-01 challenge available for %s", auth.Identifier.Value)
		}

		// Compute DNS-01 TXT record value
		keyAuth, err := client.DNS01ChallengeRecord(dnsChallenge.Token)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("compute dns-01 key auth: %w", err)
		}

		txtValue := keyAuth
		domain := auth.Identifier.Value

		// Set TXT record via DNS provider
		if err := solver.SetTXTRecord(context.Background(), domain, txtValue); err != nil {
			return nil, nil, nil, fmt.Errorf("set txt record for %s: %w", domain, err)
		}

		// Accept the challenge
		if _, err := client.Accept(context.Background(), dnsChallenge); err != nil {
			_ = solver.ClearTXTRecord(context.Background(), domain, txtValue)
			return nil, nil, nil, fmt.Errorf("accept challenge for %s: %w", domain, err)
		}

		// Wait for authorization
		if _, err := client.WaitAuthorization(context.Background(), authURL); err != nil {
			_ = solver.ClearTXTRecord(context.Background(), domain, txtValue)
			return nil, nil, nil, fmt.Errorf("wait authorization for %s: %w", domain, err)
		}

		// Cleanup TXT record
		_ = solver.ClearTXTRecord(context.Background(), domain, txtValue)
	}

	// Create order and finalize
	order, err := client.AuthorizeOrder(context.Background(), ids)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("authorize order: %w", err)
	}

	if order.Status != acme.StatusReady {
		// Wait for order to become ready
		order, err = client.WaitOrder(context.Background(), order.URI)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("wait order: %w", err)
		}
	}

	certs, _, err := client.CreateOrderCert(context.Background(), order.FinalizeURL, certKeyDER, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create order cert: %w", err)
	}

	if len(certs) == 0 {
		return nil, nil, nil, errors.New("no certificates returned")
	}

	leaf, err = x509.ParseCertificate(certs[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse leaf: %w", err)
	}

	// Build PEM output
	keyPEM, err = pemEncodePrivateKey(certKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode private key: %w", err)
	}

	var certBuf bytes.Buffer
	for _, der := range certs {
		certBuf.Write(pemEncodeCert(der))
	}
	certPEM = certBuf.Bytes()

	return leaf, keyPEM, certPEM, nil
}

// generateSigner generates a crypto.Signer suitable for acme.Client.Key.
func generateSigner(keyType string) (crypto.Signer, error) {
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "rsa":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "ecdsa", "":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// newDNSSolver creates a DNS challenge solver based on provider config.
func newDNSSolver(cfg DNSProviderConfig) (dnsChallengeSolver, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Name)) {
	case "cloudflare":
		return newCloudflareSolver(cfg.Config)
	case "alidns", "aliyun":
		return newAliDNSSolver(cfg.Config)
	case "manual", "print":
		return &manualDNSSolver{}, nil
	default:
		return nil, fmt.Errorf("unsupported dns provider: %s (supported: cloudflare, alidns, manual)", cfg.Name)
	}
}

// --- Cloudflare DNS Provider ---

type cloudflareSolver struct {
	apiToken string
	client   *http.Client
}

func newCloudflareSolver(raw json.RawMessage) (*cloudflareSolver, error) {
	var creds struct {
		AuthToken string `json:"authToken"`
	}
	if err := json.Unmarshal(raw, &creds); err != nil {
		return nil, fmt.Errorf("cloudflare config: %w", err)
	}
	if strings.TrimSpace(creds.AuthToken) == "" {
		return nil, errors.New("cloudflare requires authToken")
	}
	return &cloudflareSolver{
		apiToken: strings.TrimSpace(creds.AuthToken),
		client:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

type cfDNSRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

type cfAPIResponse struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *cloudflareSolver) cfAPI(ctx context.Context, method, path string, body io.Reader) (*cfAPIResponse, error) {
	url := "https://api.cloudflare.com/client/v4/" + strings.TrimPrefix(path, "/")
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result cfAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if !result.Success && len(result.Errors) > 0 {
		return &result, fmt.Errorf("cloudflare api error: %s", result.Errors[0].Message)
	}
	return &result, nil
}

func (s *cloudflareSolver) findZone(ctx context.Context, domain string) (string, error) {
	resp, err := s.cfAPI(ctx, http.MethodGet, fmt.Sprintf("/zones?name=%s", domain), nil)
	if err != nil {
		return "", err
	}
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(resp.Result, &zones); err != nil {
		return "", err
	}
	if len(zones) > 0 {
		return zones[0].ID, nil
	}
	// Try parent domain
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) == 2 {
		return s.findZone(ctx, parts[1])
	}
	return "", errors.New("cloudflare zone not found")
}

func (s *cloudflareSolver) SetTXTRecord(ctx context.Context, domain, value string) error {
	zoneID, err := s.findZone(ctx, domain)
	if err != nil {
		return fmt.Errorf("find zone: %w", err)
	}
	recordName := fmt.Sprintf("_acme-challenge.%s", domain)

	record := cfDNSRecord{
		Type:    "TXT",
		Name:    recordName,
		Content: value,
		TTL:     120,
	}
	payload, _ := json.Marshal(record)

	_, err = s.cfAPI(ctx, http.MethodPost, fmt.Sprintf("/zones/%s/dns_records", zoneID), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create txt record: %w", err)
	}
	return nil
}

func (s *cloudflareSolver) ClearTXTRecord(ctx context.Context, domain, value string) error {
	zoneID, err := s.findZone(ctx, domain)
	if err != nil {
		return nil // best effort
	}
	recordName := fmt.Sprintf("_acme-challenge.%s", domain)

	resp, err := s.cfAPI(ctx, http.MethodGet, fmt.Sprintf("/zones/%s/dns_records?type=TXT&name=%s", zoneID, recordName), nil)
	if err != nil {
		return nil
	}
	var records []cfDNSRecord
	if err := json.Unmarshal(resp.Result, &records); err != nil {
		return nil
	}
	for _, r := range records {
		if r.Content == value {
			_, _ = s.cfAPI(ctx, http.MethodDelete, fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, r.ID), nil)
			return nil
		}
	}
	return nil
}

// --- AliDNS Provider (placeholder) ---

type aliDNSSolver struct{}

func newAliDNSSolver(raw json.RawMessage) (*aliDNSSolver, error) {
	return &aliDNSSolver{}, nil
}

func (s *aliDNSSolver) SetTXTRecord(ctx context.Context, domain, value string) error {
	return errors.New("alidns dns-01 not yet implemented; use cloudflare or manual provider")
}

func (s *aliDNSSolver) ClearTXTRecord(ctx context.Context, domain, value string) error {
	return nil
}

// --- Manual/Print DNS Provider ---

type manualDNSSolver struct{}

func (s *manualDNSSolver) SetTXTRecord(ctx context.Context, domain, value string) error {
	fmt.Printf("\n=== DNS-01 Challenge for %s ===\n", domain)
	fmt.Printf("Create a TXT record:\n")
	fmt.Printf("  Name:    _acme-challenge.%s\n", domain)
	fmt.Printf("  Value:   %s\n", value)
	fmt.Printf("  TTL:     60\n")
	fmt.Printf("Waiting 60 seconds for DNS propagation...\n\n")

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(60 * time.Second):
	}
	return nil
}

func (s *manualDNSSolver) ClearTXTRecord(ctx context.Context, domain, value string) error {
	fmt.Printf("You can now remove the TXT record for _acme-challenge.%s\n", domain)
	return nil
}

// --- Helpers ---

func pemEncodePrivateKey(key crypto.Signer) ([]byte, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pemEncode("PRIVATE KEY", derBytes), nil
}

func pemEncodeCert(der []byte) []byte {
	return pemEncode("CERTIFICATE", der)
}

func pemEncode(typ string, der []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("-----BEGIN " + typ + "-----\n")
	for len(der) > 0 {
		chunk := len(der)
		if chunk > 64 {
			chunk = 64
		}
		buf.Write(der[:chunk])
		buf.WriteByte('\n')
		der = der[chunk:]
	}
	buf.WriteString("-----END " + typ + "-----\n")
	return buf.Bytes()
}
