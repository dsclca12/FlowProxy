package main

import (
	"strings"
	"testing"
)

func TestParseBindAddr_Standard(t *testing.T) {
	cfg, err := ParseBindAddr(":8080", 80)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Interface != "" {
		t.Fatalf("expected no interface, got %q", cfg.Interface)
	}
	if cfg.Port != 8080 {
		t.Fatalf("expected port 8080, got %d", cfg.Port)
	}
	if cfg.Address != ":8080" {
		t.Fatalf("expected address :8080, got %q", cfg.Address)
	}
}

func TestParseBindAddr_IPv4(t *testing.T) {
	cfg, err := ParseBindAddr("192.168.1.1:9000", 9000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Interface != "" {
		t.Fatalf("expected no interface, got %q", cfg.Interface)
	}
	if cfg.Port != 9000 {
		t.Fatalf("expected port 9000, got %d", cfg.Port)
	}
	if !strings.Contains(cfg.Address, "192.168.1.1") {
		t.Fatalf("expected address to contain 192.168.1.1, got %q", cfg.Address)
	}
}

func TestParseBindAddr_PortOnly(t *testing.T) {
	cfg, err := ParseBindAddr("8080", 80)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != 8080 {
		t.Fatalf("expected port 8080, got %d", cfg.Port)
	}
	if cfg.Address != ":8080" {
		t.Fatalf("expected :8080, got %q", cfg.Address)
	}
}

func TestParseBindAddr_Loopback(t *testing.T) {
	cfg, err := ParseBindAddr("127.0.0.1:9000", 9000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Interface != "" {
		t.Fatalf("expected no interface for loopback, got %q", cfg.Interface)
	}
	if cfg.Port != 9000 {
		t.Fatalf("expected port 9000, got %d", cfg.Port)
	}
}

func TestParseBindAddr_Empty(t *testing.T) {
	_, err := ParseBindAddr("", 80)
	if err == nil {
		t.Fatal("expected error for empty address")
	}
}

func TestParseBindAddr_IPv6(t *testing.T) {
	cfg, err := ParseBindAddr("[::1]:8080", 80)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Interface != "" {
		t.Fatalf("expected no interface, got %q", cfg.Interface)
	}
	if cfg.Port != 8080 {
		t.Fatalf("expected port 8080, got %d", cfg.Port)
	}
}

func TestNormalizeBindAddr(t *testing.T) {
	addr, err := normalizeBindAddr(":8080", 80)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != ":8080" {
		t.Fatalf("expected :8080, got %q", addr)
	}
}

func TestResolveAdminAddr(t *testing.T) {
	addr := resolveAdminAddr("0.0.0.0:9000")
	if addr != "0.0.0.0:9000" {
		t.Fatalf("expected 0.0.0.0:9000, got %q", addr)
	}
}

func TestResolveHTTPAddr(t *testing.T) {
	addr := resolveHTTPAddr(":80")
	if addr != ":80" {
		t.Fatalf("expected :80, got %q", addr)
	}
}

func TestIsValidIP(t *testing.T) {
	if !isValidIP("192.168.1.1") {
		t.Error("expected 192.168.1.1 to be valid IP")
	}
	if !isValidIP("::1") {
		t.Error("expected ::1 to be valid IP")
	}
	if isValidIP("eth0") {
		t.Error("expected eth0 not to be valid IP")
	}
}

func TestIsWildcardHost(t *testing.T) {
	if !isWildcardHost("") {
		t.Error("expected empty string to be wildcard")
	}
	if !isWildcardHost("0.0.0.0") {
		t.Error("expected 0.0.0.0 to be wildcard")
	}
	if !isWildcardHost("::") {
		t.Error("expected :: to be wildcard")
	}
	if isWildcardHost("127.0.0.1") {
		t.Error("expected 127.0.0.1 not to be wildcard")
	}
}
