package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// gRPC-related constants.
const (
	grpcContentType       = "application/grpc"
	grpcWebContentType    = "application/grpc-web"
	grpcContentTypePrefix = "application/grpc"
)

// IsGRPCRequest checks whether an HTTP request is a gRPC call
// by examining the Content-Type header.
func IsGRPCRequest(req *http.Request) bool {
	if req == nil || req.Header == nil {
		return false
	}
	ct := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	return strings.HasPrefix(ct, grpcContentTypePrefix)
}

// IsGRPCWebRequest checks whether a request is a gRPC-Web call.
func IsGRPCWebRequest(req *http.Request) bool {
	if req == nil || req.Header == nil {
		return false
	}
	ct := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	return ct == grpcWebContentType || strings.HasPrefix(ct, grpcWebContentType+";")
}

// ensureH2CTransport wraps an http.Transport for gRPC h2c (cleartext HTTP/2).
//
// For HTTPS upstreams: HTTP/2 is negotiated via ALPN (ForceAttemptHTTP2).
// For cleartext upstreams: returns an h2cRoundTripper that handles both
// h2c gRPC and regular HTTP/1.1 requests.
func ensureH2CTransport(transport *http.Transport, timeout time.Duration) http.RoundTripper {
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}

	// TLS: HTTP/2 via ALPN
	if transport.TLSClientConfig != nil {
		transport.ForceAttemptHTTP2 = true
		return transport
	}

	// Cleartext: use h2c-aware round tripper
	origDialContext := transport.DialContext
	timeoutDialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	dialFn := origDialContext
	if dialFn == nil {
		dialFn = timeoutDialer.DialContext
	}

	h2cTransport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialFn(ctx, network, addr)
		},
	}

	return &h2cRoundTripper{
		h2c:  h2cTransport,
		base: transport.RoundTrip,
	}
}

// h2cRoundTripper routes gRPC requests through the h2c (HTTP/2 cleartext)
// transport, and falls back to the standard HTTP/1.1 transport for all
// other requests.
type h2cRoundTripper struct {
	h2c  *http2.Transport
	base func(*http.Request) (*http.Response, error)
}

func (rt *h2cRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}
	if IsGRPCRequest(req) && req.URL.Scheme != "https" {
		return rt.h2c.RoundTrip(req)
	}
	if rt.base != nil {
		return rt.base(req)
	}
	return nil, fmt.Errorf("h2cRoundTripper: no base transport")
}

// grpcDirector adjusts the ReverseProxy director for gRPC requests.
// It preserves the original :authority header and avoids rewriting
// the host in ways that break gRPC protocol negotiation.
func grpcDirector(originalDirector func(*http.Request)) func(*http.Request) {
	return func(req *http.Request) {
		if !IsGRPCRequest(req) {
			originalDirector(req)
			return
		}

		// Preserve the original target host for gRPC
		originalHost := req.Host

		// Call the original director to set up the target URL
		originalDirector(req)

		// gRPC requires the :authority pseudo-header to match the upstream.
		// Restore the host that the original director set.
		if originalHost != "" {
			req.Host = originalHost
		}

		// gRPC uses TE: trailers (required by spec)
		if req.Header.Get("TE") == "" {
			req.Header.Set("TE", "trailers")
		}
	}
}

// grpcErrorHandler returns a custom error handler for gRPC proxy errors.
func grpcErrorHandler(next func(http.ResponseWriter, *http.Request, error)) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {
		if !IsGRPCRequest(req) {
			next(w, req, err)
			return
		}

		// For gRPC, return a proper gRPC error response
		w.Header().Set("Content-Type", grpcContentType)
		w.Header().Set("Grpc-Status", "14") // UNAVAILABLE
		w.Header().Set("Grpc-Message", http.StatusText(http.StatusServiceUnavailable))
		w.WriteHeader(http.StatusOK)
	}
}

// gRPC support for the h2c handler in the HTTP server.
// newH2CHandler wraps an existing handler with h2c support for
// incoming gRPC connections over cleartext HTTP/2.
func newH2CHandler(next http.Handler) http.Handler {
	// Use golang.org/x/net/http2/h2c which provides
	// HTTP/2 cleartext (h2c) upgrade support
	h2s := &http2.Server{
		IdleTimeout: 90 * time.Second,
	}
	return h2c.NewHandler(next, h2s)
}
