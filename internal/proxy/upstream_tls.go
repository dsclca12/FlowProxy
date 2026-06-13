package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"flowproxy/internal/site"
)

func newUpstreamTransport(targetURL *url.URL, cfg site.UpstreamTLSConfig, timeouts site.TimeoutConfig, grpcH2C bool) (http.RoundTripper, error) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("http default transport is invalid")
	}
	transport := base.Clone()
	applyTransportTimeouts(transport, timeouts)

	if strings.ToLower(strings.TrimSpace(targetURL.Scheme)) != "https" {
		if grpcH2C {
			connectTimeout := timeouts.ConnectMillis
			if connectTimeout <= 0 {
				connectTimeout = 5000
			}
			return ensureH2CTransport(transport, time.Duration(connectTimeout)*time.Millisecond), nil
		}
		return transport, nil
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if transport.TLSClientConfig != nil {
		tlsCfg = transport.TLSClientConfig.Clone()
	}
	tlsCfg.InsecureSkipVerify = cfg.InsecureSkipVerify
	tlsCfg.ServerName = strings.TrimSpace(cfg.ServerName)

	rootCAFile := strings.TrimSpace(cfg.RootCAFile)
	rootCAPEM := strings.TrimSpace(cfg.RootCAPEM)
	if rootCAFile != "" || rootCAPEM != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if rootCAFile != "" {
			data, err := os.ReadFile(rootCAFile)
			if err != nil {
				return nil, fmt.Errorf("read upstream rootCAFile %s: %w", rootCAFile, err)
			}
			if !roots.AppendCertsFromPEM(data) {
				return nil, fmt.Errorf("upstream rootCAFile %s contains no valid PEM cert", rootCAFile)
			}
		}
		if rootCAPEM != "" {
			if !roots.AppendCertsFromPEM([]byte(rootCAPEM)) {
				return nil, fmt.Errorf("upstream rootCAPem contains no valid PEM cert")
			}
		}
		tlsCfg.RootCAs = roots
	}

	transport.TLSClientConfig = tlsCfg

	if grpcH2C {
		connectTimeout := timeouts.ConnectMillis
		if connectTimeout <= 0 {
			connectTimeout = 5000
		}
		return ensureH2CTransport(transport, time.Duration(connectTimeout)*time.Millisecond), nil
	}

	return transport, nil
}

func applyTransportTimeouts(transport *http.Transport, cfg site.TimeoutConfig) {
	if transport == nil {
		return
	}
	connectTimeout := durationFromMillis(cfg.ConnectMillis)
	keepAlive := durationFromMillis(cfg.BackendKeepaliveMillis)
	nextDialer := &net.Dialer{
		Timeout:   connectTimeout,
		KeepAlive: 30 * time.Second,
	}
	if cfg.BackendKeepaliveDisabled {
		nextDialer.KeepAlive = -1
	} else if keepAlive > 0 {
		nextDialer.KeepAlive = keepAlive
	}
	transport.DialContext = localhostFallbackDialContext(nextDialer)

	if d := durationFromMillis(cfg.ResponseHeaderMillis); d > 0 {
		transport.ResponseHeaderTimeout = d
	} else {
		transport.ResponseHeaderTimeout = 30 * time.Second
	}
	if d := durationFromMillis(cfg.ExpectContinueMillis); d > 0 {
		transport.ExpectContinueTimeout = d
	}
	if d := durationFromMillis(cfg.IdleConnMillis); d > 0 {
		transport.IdleConnTimeout = d
	} else {
		transport.IdleConnTimeout = 90 * time.Second
	}
	if d := durationFromMillis(cfg.TLSHandshakeMillis); d > 0 {
		transport.TLSHandshakeTimeout = d
	} else {
		transport.TLSHandshakeTimeout = 10 * time.Second
	}
	// Set sensible connection pool defaults
	if cfg.MaxIdleConnsPerHost > 0 {
		transport.MaxIdleConnsPerHost = cfg.MaxIdleConnsPerHost
	} else {
		transport.MaxIdleConnsPerHost = 10
	}
	if cfg.MaxBackendConnections > 0 {
		transport.MaxConnsPerHost = cfg.MaxBackendConnections
	} else {
		transport.MaxConnsPerHost = 0 // unlimited
	}
	transport.MaxIdleConns = 100
	transport.ForceAttemptHTTP2 = true
}

func localhostFallbackDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, address)
		if err == nil {
			return conn, nil
		}
		host, port, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, err
		}
		host = strings.Trim(strings.TrimSpace(host), "[]")
		if !strings.EqualFold(host, "localhost") {
			return nil, err
		}
		for _, ip := range []string{"127.0.0.1", "::1"} {
			conn, fallbackErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if fallbackErr == nil {
				return conn, nil
			}
		}
		return nil, err
	}
}
