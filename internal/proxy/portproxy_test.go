package proxy

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"flowproxy/internal/site"
)

func TestExtractL4Sites(t *testing.T) {
	// Test TCP site extraction
	tcpSite := site.Site{
		ID:         "tcp-site-1",
		Name:       "MySQL Forward",
		Protocol:   "tcp",
		ListenPort: 3307,
		Upstream:   "http://192.168.1.100:3306",
		Enabled:    true,
	}
	sites := []site.Site{tcpSite}
	l4s := ExtractL4Sites(sites)
	if len(l4s) != 1 {
		t.Fatalf("expected 1 L4 site, got %d", len(l4s))
	}
	if l4s[0].Protocol != ProtocolTCP {
		t.Fatalf("expected TCP protocol, got %s", l4s[0].Protocol)
	}
	if l4s[0].Port != 3307 {
		t.Fatalf("expected port 3307, got %d", l4s[0].Port)
	}
	if l4s[0].Upstream != "192.168.1.100:3306" {
		t.Fatalf("expected upstream 192.168.1.100:3306, got %s", l4s[0].Upstream)
	}
	if l4s[0].SiteID != "tcp-site-1" {
		t.Fatalf("expected site ID tcp-site-1, got %s", l4s[0].SiteID)
	}
}

func TestExtractL4Sites_Disabled(t *testing.T) {
	disabled := site.Site{
		ID:         "disabled-tcp",
		Protocol:   "tcp",
		ListenPort: 3307,
		Upstream:   "http://10.0.0.1:3306",
		Enabled:    false,
	}
	l4s := ExtractL4Sites([]site.Site{disabled})
	if len(l4s) != 0 {
		t.Fatalf("expected 0 L4 sites for disabled site, got %d", len(l4s))
	}
}

func TestExtractL4Sites_NoPort(t *testing.T) {
	noPort := site.Site{
		ID:       "no-port",
		Protocol: "tcp",
		Upstream: "http://10.0.0.1:3306",
		Enabled:  true,
	}
	l4s := ExtractL4Sites([]site.Site{noPort})
	if len(l4s) != 0 {
		t.Fatalf("expected 0 L4 sites without listenPort, got %d", len(l4s))
	}
}

func TestExtractL4Sites_MixedL4AndHTTP(t *testing.T) {
	sites := []site.Site{
		{
			ID:         "tcp",
			Protocol:   "tcp",
			ListenPort: 3307,
			Upstream:   "http://10.0.0.1:3306",
			Enabled:    true,
		},
		{
			ID:         "udp",
			Protocol:   "udp",
			ListenPort: 5353,
			Upstream:   "udp://10.0.0.1:53",
			Enabled:    true,
		},
		{
			ID:       "http",
			Domain:   "example.com",
			Upstream: "http://10.0.0.1:8080",
			Enabled:  true,
		},
	}
	l4s := ExtractL4Sites(sites)
	if len(l4s) != 2 {
		t.Fatalf("expected 2 L4 sites, got %d", len(l4s))
	}
}

func TestExtractL4Sites_HostPortUpstream(t *testing.T) {
	s := site.Site{
		ID:         "raw-tcp",
		Protocol:   "tcp",
		ListenPort: 2222,
		Upstream:   "192.168.1.1:22",
		Enabled:    true,
	}
	l4s := ExtractL4Sites([]site.Site{s})
	if len(l4s) != 1 {
		t.Fatalf("expected 1 L4 site, got %d", len(l4s))
	}
	if l4s[0].Upstream != "192.168.1.1:22" {
		t.Fatalf("expected upstream 192.168.1.1:22, got %s", l4s[0].Upstream)
	}
}

func TestIsL4Site(t *testing.T) {
	tests := []struct {
		site     site.Site
		expected bool
	}{
		{site.Site{Protocol: "tcp"}, true},
		{site.Site{Protocol: "udp"}, true},
		{site.Site{Protocol: "tls"}, true},
		{site.Site{Protocol: "TCP"}, true},
		{site.Site{Protocol: "UDP"}, true},
		{site.Site{Protocol: ""}, false},
		{site.Site{Protocol: "http"}, false},
		{site.Site{Protocol: "invalid"}, false},
	}
	for _, tt := range tests {
		result := IsL4Site(tt.site)
		if result != tt.expected {
			t.Errorf("IsL4Site(%q) = %v, want %v", tt.site.Protocol, result, tt.expected)
		}
	}
}

func TestExtractHostPort(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://192.168.1.100:3306", "192.168.1.100:3306"},
		{"https://example.com:443", "example.com:443"},
		{"http://10.0.0.1:80", "10.0.0.1:80"},
		{"https://example.com", "example.com:443"},
		{"http://example.com", "example.com:80"},
		{"192.168.1.100:3306", "192.168.1.100:3306"},
		{"example.com:8080", "example.com:8080"},
		{"", ""},
	}
	for _, tt := range tests {
		result := extractHostPort(tt.input)
		if result != tt.expected {
			t.Errorf("extractHostPort(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestL4Proxy_TCPEcho(t *testing.T) {
	// Start echo server
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo listener: %v", err)
	}
	echoPort := echoListener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						c.Close()
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()
	defer echoListener.Close()

	// Create L4 proxy pointing to echo server
	l4 := NewL4Proxy()
	defer l4.Shutdown(context.Background())

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	proxyPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	l4.Sync([]L4SiteConfig{
		{
			SiteID:   "echo-test",
			Protocol: ProtocolTCP,
			Port:     proxyPort,
			Upstream: fmt.Sprintf("127.0.0.1:%d", echoPort),
			Enabled:  true,
		},
	}, nil)

	// Give the proxy a moment to start
	time.Sleep(100 * time.Millisecond)

	// Connect and test
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	testMsg := []byte("Hello L4 Proxy!")
	if _, err := conn.Write(testMsg); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	reply := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatalf("failed to read reply: %v", err)
	}

	if string(reply[:n]) != string(testMsg) {
		t.Fatalf("expected echo %q, got %q", string(testMsg), string(reply[:n]))
	}
}

func TestL4Proxy_DisabledEntry(t *testing.T) {
	l4 := NewL4Proxy()
	defer l4.Shutdown(context.Background())

	// Sync with disabled entry - should not start a listener
	l4.Sync([]L4SiteConfig{
		{
			SiteID:   "disabled",
			Protocol: ProtocolTCP,
			Port:     19999,
			Upstream: "127.0.0.1:1",
			Enabled:  false,
		},
	}, nil)

	// Verify no port is being listened on
	ports := l4.ListenerPorts()
	if len(ports) != 0 {
		t.Fatalf("expected 0 ports for disabled entry, got %d", len(ports))
	}
}
