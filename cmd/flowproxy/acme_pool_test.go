package main

import (
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"flowproxy/internal/certmgr"
)

func TestNormalizeACMEProfileDefaults(t *testing.T) {
	profile, err := normalizeACMEProfile(certmgr.ACMEConfig{}, "ops@example.com")
	if err != nil {
		t.Fatalf("normalize profile failed: %v", err)
	}
	if profile.directory != acme.LetsEncryptURL {
		t.Fatalf("unexpected default directory: %s", profile.directory)
	}
	if profile.email != "ops@example.com" {
		t.Fatalf("unexpected default email: %s", profile.email)
	}
	if profile.keyType != "ecdsa" {
		t.Fatalf("unexpected default key type: %s", profile.keyType)
	}
	if profile.renewBefore != 30*24*time.Hour {
		t.Fatalf("unexpected default renewBefore: %s", profile.renewBefore)
	}
}

func TestNormalizeACMEProfileCustomDirectory(t *testing.T) {
	profile, err := normalizeACMEProfile(certmgr.ACMEConfig{
		Provider:        "custom",
		DirectoryURL:    "https://acme.example.com/directory",
		KeyType:         "rsa",
		RenewBeforeDays: 12,
	}, "")
	if err != nil {
		t.Fatalf("normalize profile failed: %v", err)
	}
	if profile.directory != "https://acme.example.com/directory" {
		t.Fatalf("unexpected directory: %s", profile.directory)
	}
	if profile.keyType != "rsa" {
		t.Fatalf("unexpected key type: %s", profile.keyType)
	}
	if profile.renewBefore != 12*24*time.Hour {
		t.Fatalf("unexpected renewBefore: %s", profile.renewBefore)
	}
}

func TestNormalizeACMEProfileRejectsUnsupportedValues(t *testing.T) {
	if _, err := normalizeACMEProfile(certmgr.ACMEConfig{
		Challenge: "tls-alpn-01",
	}, ""); err == nil {
		t.Fatalf("expected challenge validation error")
	}

	if _, err := normalizeACMEProfile(certmgr.ACMEConfig{
		KeyType: "ed25519",
	}, ""); err == nil {
		t.Fatalf("expected key type validation error")
	}
}
