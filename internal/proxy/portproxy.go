// Package proxy implements L4 TCP/UDP/TLS port forwarding proxy.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"flowproxy/internal/site"
)

// PortProtocol represents the L4 protocol type for port forwarding.
type PortProtocol string

const (
	ProtocolTCP PortProtocol = "tcp"
	ProtocolUDP PortProtocol = "udp"
	ProtocolTLS PortProtocol = "tls"
)

func ParsePortProtocol(s string) (PortProtocol, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp":
		return ProtocolTCP, true
	case "udp":
		return ProtocolUDP, true
	case "tls":
		return ProtocolTLS, true
	default:
		return "", false
	}
}

// L4Proxy manages TCP/UDP/TLS port forwarding entries.
type L4Proxy struct {
	mu      sync.Mutex
	entries map[string]*l4ProxyEntry
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
	closed  bool
}

type l4ProxyEntry struct {
	siteID   string
	protocol PortProtocol
	iface    string // network interface name, "" = all
	port     int
	upstream string
	timeout  time.Duration

	// Run-time state
	listener   net.Listener
	udpConn    *net.UDPConn
	serverCtx  context.Context
	serverStop context.CancelFunc
}

// NewL4Proxy creates a new L4 port forwarding manager.
func NewL4Proxy() *L4Proxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &L4Proxy{
		entries: make(map[string]*l4ProxyEntry),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// entryKey builds a unique key for an L4 entry.
func entryKey(siteID string, protocol PortProtocol, port int, iface string) string {
	return fmt.Sprintf("%s:%s:%d:%s", siteID, protocol, port, iface)
}

// Sync reconciles the desired L4 sites with the running proxy entries.
func (p *L4Proxy) Sync(sites []L4SiteConfig, reserved map[int]struct{}) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}

	// Build desired set: expand multi-interface entries
	desired := make(map[string]L4SiteConfig)
	for _, s := range sites {
		if !s.Enabled || s.Port <= 0 {
			continue
		}
		if _, blocked := reserved[s.Port]; blocked {
			log.Printf("L4 proxy: port %d is reserved, skipping site %s", s.Port, s.SiteID)
			continue
		}
		ifaces := s.EffectiveInterfaces()
		for _, iface := range ifaces {
			cfg := L4SiteConfig{
				SiteID:         s.SiteID,
				Protocol:       s.Protocol,
				Port:           s.Port,
				Upstream:       s.Upstream,
				BindInterfaces: []string{iface},
				Timeout:        s.Timeout,
				Enabled:        s.Enabled,
			}
			key := entryKey(cfg.SiteID, cfg.Protocol, cfg.Port, iface)
			desired[key] = cfg
		}
	}

	// Stop entries not in desired
	toStop := make([]*l4ProxyEntry, 0)
	for key, entry := range p.entries {
		if _, ok := desired[key]; ok {
			continue
		}
		toStop = append(toStop, entry)
		delete(p.entries, key)
	}
	p.mu.Unlock()

	// Stop removed entries
	for _, entry := range toStop {
		p.stopEntry(entry)
	}

	// Start new entries
	toStart := make([]L4SiteConfig, 0)
	p.mu.Lock()
	for key, cfg := range desired {
		if _, exists := p.entries[key]; exists {
			continue
		}
		toStart = append(toStart, cfg)
	}
	p.mu.Unlock()

	for _, cfg := range toStart {
		p.startEntry(cfg)
	}
}

// L4SiteConfig describes a single L4 port forwarding entry.
type L4SiteConfig struct {
	SiteID         string
	Protocol       PortProtocol
	Port           int
	Upstream       string   // e.g., "192.168.1.100:3306"
	BindInterfaces []string // e.g., ["eth0", "eth1"]; empty = all
	Timeout        time.Duration
	Enabled        bool
}

// EffectiveInterfaces returns the list of network interfaces to bind to.
// An empty/single-empty result means all interfaces.
func (c L4SiteConfig) EffectiveInterfaces() []string {
	cleaned := make([]string, 0, len(c.BindInterfaces))
	for _, iface := range c.BindInterfaces {
		if strings.TrimSpace(iface) != "" {
			cleaned = append(cleaned, strings.TrimSpace(iface))
		}
	}
	if len(cleaned) > 0 {
		return cleaned
	}
	return []string{""}
}

// startEntry starts a single L4 proxy listener on the given interface.
// iface is empty string for all interfaces.
func (p *L4Proxy) startEntry(cfg L4SiteConfig) {
	iface := ""
	if len(cfg.BindInterfaces) > 0 && strings.TrimSpace(cfg.BindInterfaces[0]) != "" {
		iface = strings.TrimSpace(cfg.BindInterfaces[0])
	}

	ctx, stop := context.WithCancel(p.ctx)
	entry := &l4ProxyEntry{
		siteID:     cfg.SiteID,
		protocol:   cfg.Protocol,
		iface:      iface,
		port:       cfg.Port,
		upstream:   cfg.Upstream,
		timeout:    cfg.Timeout,
		serverCtx:  ctx,
		serverStop: stop,
	}

	addr := fmt.Sprintf(":%d", cfg.Port)
	if iface != "" {
		// Resolve interface name to its IP address
		if ip, err := resolveIfaceIP(iface); err == nil {
			addr = net.JoinHostPort(ip, strconv.Itoa(cfg.Port))
		} else {
			log.Printf("L4 proxy: interface %q not found for site %s, falling back to all interfaces: %v", iface, cfg.SiteID, err)
			iface = ""
		}
	}

	p.mu.Lock()
	key := entryKey(cfg.SiteID, cfg.Protocol, cfg.Port, iface)
	p.entries[key] = entry
	p.mu.Unlock()

	switch cfg.Protocol {
	case ProtocolTCP:
		p.startTCP(entry, addr)
	case ProtocolTLS:
		p.startTCP(entry, addr) // TLS passthrough uses TCP forwarding
	case ProtocolUDP:
		p.startUDP(entry, addr)
	default:
		log.Printf("L4 proxy: unsupported protocol %s for site %s", cfg.Protocol, cfg.SiteID)
	}
}

// startTCP starts a TCP listener and connection handler.
func (p *L4Proxy) startTCP(entry *l4ProxyEntry, addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("L4 TCP proxy: failed to listen on %s for site %s: %v", addr, entry.siteID, err)
		entry.serverStop()
		p.removeEntry(entry.siteID, entry.protocol, entry.port, entry.iface)
		return
	}
	entry.listener = listener
	log.Printf("L4 TCP proxy: listening on %s -> %s (site: %s)", addr, entry.upstream, entry.siteID)

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-entry.serverCtx.Done():
					return
				default:
					log.Printf("L4 TCP proxy: accept error on %s: %v", addr, err)
					continue
				}
			}
			p.wg.Add(1)
			go p.handleTCPConn(conn, entry)
		}
	}()
}

// handleTCPConn handles a single TCP connection.
func (p *L4Proxy) handleTCPConn(client net.Conn, entry *l4ProxyEntry) {
	defer p.wg.Done()
	defer client.Close()

	upstreamAddr := entry.upstream
	dialer := &net.Dialer{}
	if entry.timeout > 0 {
		dialer.Timeout = entry.timeout
	}

	upstream, err := dialer.DialContext(entry.serverCtx, "tcp", upstreamAddr)
	if err != nil {
		log.Printf("L4 TCP proxy: dial upstream %s failed for site %s: %v", upstreamAddr, entry.siteID, err)
		return
	}
	defer upstream.Close()

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(upstream, client)
		upstream.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(client, upstream)
		client.Close()
	}()

	wg.Wait()
}

// startUDP starts a UDP listener and packet handler.
func (p *L4Proxy) startUDP(entry *l4ProxyEntry, addr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Printf("L4 UDP proxy: resolve addr %s failed for site %s: %v", addr, entry.siteID, err)
		entry.serverStop()
		p.removeEntry(entry.siteID, entry.protocol, entry.port, entry.iface)
		return
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("L4 UDP proxy: listen on %s failed for site %s: %v", addr, entry.siteID, err)
		entry.serverStop()
		p.removeEntry(entry.siteID, entry.protocol, entry.port, entry.iface)
		return
	}
	entry.udpConn = conn
	log.Printf("L4 UDP proxy: listening on %s -> %s (site: %s)", addr, entry.upstream, entry.siteID)

	// Resolve upstream UDP address once
	upstreamAddr, err := net.ResolveUDPAddr("udp", entry.upstream)
	if err != nil {
		log.Printf("L4 UDP proxy: resolve upstream %s failed for site %s: %v", entry.upstream, entry.siteID, err)
		conn.Close()
		entry.serverStop()
		p.removeEntry(entry.siteID, entry.protocol, entry.port, entry.iface)
		return
	}

	p.wg.Add(1)
	go p.handleUDPPackets(conn, entry, upstreamAddr)
}

// udpSession tracks a UDP client session for response routing.
type udpSession struct {
	clientAddr *net.UDPAddr
	upstream   *net.UDPConn
	lastSeen   time.Time
}

// handleUDPPackets handles UDP packet forwarding with session tracking.
func (p *L4Proxy) handleUDPPackets(conn *net.UDPConn, entry *l4ProxyEntry, upstreamAddr *net.UDPAddr) {
	defer p.wg.Done()
	defer conn.Close()

	sessions := make(map[string]*udpSession)
	var sessionsMu sync.Mutex
	cleanupTicker := time.NewTicker(5 * time.Minute)
	defer cleanupTicker.Stop()

	buf := make([]byte, 65507) // max UDP payload

	for {
		select {
		case <-entry.serverCtx.Done():
			return
		case <-cleanupTicker.C:
			sessionsMu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for key, s := range sessions {
				if s.lastSeen.Before(cutoff) {
					if s.upstream != nil {
						s.upstream.Close()
					}
					delete(sessions, key)
				}
			}
			sessionsMu.Unlock()
		default:
		}

		// Set read deadline for periodic cleanup checks
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-entry.serverCtx.Done():
				return
			default:
				log.Printf("L4 UDP proxy: read error for site %s: %v", entry.siteID, err)
				return
			}
		}

		clientKey := clientAddr.String()

		sessionsMu.Lock()
		session, exists := sessions[clientKey]
		if !exists {
			// Open upstream connection per client
			upstreamConn, err := net.DialUDP("udp", nil, upstreamAddr)
			if err != nil {
				sessionsMu.Unlock()
				log.Printf("L4 UDP proxy: dial upstream %s for site %s: %v", entry.upstream, entry.siteID, err)
				continue
			}
			session = &udpSession{
				clientAddr: clientAddr,
				upstream:   upstreamConn,
				lastSeen:   time.Now(),
			}
			sessions[clientKey] = session

			// Start response listener for this session
			p.wg.Add(1)
			go p.udpResponseReader(session, conn, entry)
		} else {
			session.lastSeen = time.Now()
		}
		sessionsMu.Unlock()

		// Forward packet to upstream
		if _, err := session.upstream.Write(buf[:n]); err != nil {
			log.Printf("L4 UDP proxy: write to upstream for site %s: %v", entry.siteID, err)
		}
	}
}

// udpResponseReader reads UDP responses from an upstream and sends them back to the client.
func (p *L4Proxy) udpResponseReader(session *udpSession, clientConn *net.UDPConn, entry *l4ProxyEntry) {
	defer p.wg.Done()
	defer session.upstream.Close()

	buf := make([]byte, 65507)
	for {
		select {
		case <-entry.serverCtx.Done():
			return
		default:
		}

		session.upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := session.upstream.Read(buf)
		if err != nil {
			return
		}

		select {
		case <-entry.serverCtx.Done():
			return
		default:
		}

		if _, err := clientConn.WriteToUDP(buf[:n], session.clientAddr); err != nil {
			log.Printf("L4 UDP proxy: write to client for site %s: %v", entry.siteID, err)
			return
		}
	}
}

// stopEntry gracefully stops a single proxy entry.
func (p *L4Proxy) stopEntry(entry *l4ProxyEntry) {
	if entry == nil {
		return
	}
	entry.serverStop()
	if entry.listener != nil {
		entry.listener.Close()
	}
	if entry.udpConn != nil {
		entry.udpConn.Close()
	}
	log.Printf("L4 proxy: stopped %s on :%d (site: %s)", entry.protocol, entry.port, entry.siteID)
}

// removeEntry removes an entry from the map (must NOT hold lock).
func (p *L4Proxy) removeEntry(siteID string, protocol PortProtocol, port int, iface string) {
	key := entryKey(siteID, protocol, port, iface)
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.entries, key)
}

// Shutdown gracefully stops all L4 proxies.
func (p *L4Proxy) Shutdown(ctx context.Context) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true

	entries := make([]*l4ProxyEntry, 0, len(p.entries))
	for _, entry := range p.entries {
		entries = append(entries, entry)
	}
	p.entries = make(map[string]*l4ProxyEntry)
	p.mu.Unlock()

	for _, entry := range entries {
		p.stopEntry(entry)
	}

	p.cancel()

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

// extractL4Sites extracts L4 port forwarding sites from a list of sites.
func ExtractL4Sites(sites []site.Site) []L4SiteConfig {
	var out []L4SiteConfig
	for _, s := range sites {
		if !s.Enabled || s.ListenPort <= 0 {
			continue
		}
		protocol, ok := ParsePortProtocol(s.Protocol)
		if !ok {
			continue
		}
		upstream := strings.TrimSpace(s.Upstream)
		if upstream == "" {
			for _, up := range s.Upstreams {
				u := strings.TrimSpace(up.URL)
				if u != "" {
					upstream = extractHostPort(u)
					break
				}
			}
		} else {
			upstream = extractHostPort(upstream)
		}
		if upstream == "" {
			continue
		}
		var timeout time.Duration
		if s.Timeouts.RequestMillis > 0 {
			timeout = time.Duration(s.Timeouts.RequestMillis) * time.Millisecond
		}
		out = append(out, L4SiteConfig{
			SiteID:         s.ID,
			Protocol:       protocol,
			Port:           s.ListenPort,
			Upstream:       upstream,
			BindInterfaces: cleanBindInterfaces(s.BindInterfaces),
			Timeout:        timeout,
			Enabled:        s.Enabled,
		})
	}
	return out
}

// extractHostPort extracts host:port from a URL or host:port string.
func extractHostPort(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Try as URL first
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" || u.Scheme == "tls" {
				port = "443"
			} else {
				port = "80"
			}
		}
		return net.JoinHostPort(host, port)
	}
	// Check if already host:port
	_, _, err := net.SplitHostPort(raw)
	if err == nil {
		return raw
	}
	// Maybe just host, append default port
	host := strings.TrimSpace(raw)
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, "80")
}

// IsL4Site checks if a site is configured for L4 port forwarding.
func IsL4Site(s site.Site) bool {
	_, ok := ParsePortProtocol(s.Protocol)
	return ok
}

// L4ProxyListenerPorts returns all port numbers currently used by L4 proxy entries.
func (p *L4Proxy) ListenerPorts() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	seen := make(map[int]struct{})
	for _, entry := range p.entries {
		seen[entry.port] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for port := range seen {
		out = append(out, port)
	}
	return out
}

// cleanBindInterfaces filters and returns non-empty, trimmed interface names.
func cleanBindInterfaces(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if v := strings.TrimSpace(item); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// resolveIfaceIP resolves a network interface name to its preferred IPv4 address.
func resolveIfaceIP(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", fmt.Errorf("interface %q: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("interface %q addrs: %w", name, err)
	}
	// Prefer IPv4 (include loopback)
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipv4 := ipNet.IP.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}
	// Fallback to first non-loopback address
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.IsLoopback() {
			continue
		}
		return ipNet.IP.String(), nil
	}
	return "", fmt.Errorf("interface %q has no usable address", name)
}

// Wait blocks until all L4 proxy goroutines finish (for graceful shutdown).
func (p *L4Proxy) Wait() {
	p.wg.Wait()
}
