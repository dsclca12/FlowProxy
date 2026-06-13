package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// BindConfig holds the parsed interface binding and listen address.
type BindConfig struct {
	Interface string // empty means no specific interface
	Address   string // resolved IP:port or :port
	Port      int
	Host      string
}

// ParseBindAddr parses an address that may include an interface binding.
// Supported formats:
//
//	":8080"         -> no binding, port 8080
//	"0.0.0.0:8080"  -> no binding, port 8080
//	"eth0:8080"     -> bind to eth0, port 8080
//	"eth0:192.168.1.1:8080" -> explicit IP on eth0 (unusual but supported)
//	"eth1"          -> bind to eth1's primary IP, use default port if not provided
func ParseBindAddr(raw string, defaultPort int) (*BindConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty address")
	}

	// Try standard host:port format first
	host, port, err := net.SplitHostPort(raw)
	if err == nil {
		// Check if host part is actually an interface name
		if host != "" && !isValidIP(host) && !isWildcardHost(host) {
			// Could be interface:port format
			ifaceIP, err := resolveInterfaceIP(host)
			if err == nil {
				portNum, _ := strconv.Atoi(port)
				return &BindConfig{
					Interface: host,
					Address:   net.JoinHostPort(ifaceIP, port),
					Port:      portNum,
					Host:      ifaceIP,
				}, nil
			}
		}
		portNum, _ := strconv.Atoi(port)
		if host == "" {
			return &BindConfig{Address: raw, Port: portNum}, nil
		}
		return &BindConfig{Address: raw, Port: portNum, Host: host}, nil
	}

	// Check if raw is just an interface name with colon, like ":eth0"
	if strings.HasPrefix(raw, ":") {
		ifaceName := strings.TrimPrefix(raw, ":")
		if ifaceName != "" && !isValidIP(ifaceName) && !isWildcardHost(ifaceName) {
			ifaceIP, err := resolveInterfaceIP(ifaceName)
			if err == nil {
				addr := net.JoinHostPort(ifaceIP, strconv.Itoa(defaultPort))
				return &BindConfig{
					Interface: ifaceName,
					Address:   addr,
					Port:      defaultPort,
					Host:      ifaceIP,
				}, nil
			}
		}
		// Fallback: treat as :port
		if portNum, err := strconv.Atoi(ifaceName); err == nil {
			return &BindConfig{Address: raw, Port: portNum}, nil
		}
		return &BindConfig{Address: raw, Port: defaultPort}, nil
	}

	// Try to parse as interface name only (no port)
	if !isValidIP(raw) && !isWildcardHost(raw) {
		ifaceIP, err := resolveInterfaceIP(raw)
		if err == nil {
			addr := net.JoinHostPort(ifaceIP, strconv.Itoa(defaultPort))
			return &BindConfig{
				Interface: raw,
				Address:   addr,
				Port:      defaultPort,
				Host:      ifaceIP,
			}, nil
		}
	}

	// Try as port number only
	if portNum, err := strconv.Atoi(raw); err == nil {
		return &BindConfig{Address: ":" + raw, Port: portNum}, nil
	}

	// Treat as host:port with no colon (e.g. "192.168.1.1" with default port)
	return &BindConfig{Address: net.JoinHostPort(raw, strconv.Itoa(defaultPort)), Port: defaultPort, Host: raw}, nil
}

// ResolveInterfaceIP resolves an interface name to its primary IPv4 address.
func resolveInterfaceIP(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", fmt.Errorf("interface %s: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("interface %s addrs: %w", name, err)
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
	// Fallback: return first IPv6
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
	return "", fmt.Errorf("interface %s has no usable IP address", name)
}

// ResolveInterfaceIPv6 resolves an interface name to its IPv6 address.
func ResolveInterfaceIPv6(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", fmt.Errorf("interface %s: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("interface %s addrs: %w", name, err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.IsLoopback() {
			continue
		}
		if ipNet.IP.To4() == nil {
			return ipNet.IP.String(), nil
		}
	}
	return "", fmt.Errorf("interface %s has no usable IPv6 address", name)
}

// ResolveInterfaceAnyIP resolves to any IP (IPv4 preferred) on the interface.
func ResolveInterfaceAnyIP(name string) (string, error) {
	return resolveInterfaceIP(name)
}

// IsInterfaceName checks if a string looks like a network interface name.
func IsInterfaceName(s string) bool {
	if s == "" || isValidIP(s) || isWildcardHost(s) {
		return false
	}
	_, err := net.InterfaceByName(s)
	return err == nil
}

// isValidIP checks if s is a valid IP address.
func isValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

// isWildcardHost checks for wildcard listen addresses.
func isWildcardHost(s string) bool {
	return s == "" || s == "0.0.0.0" || s == "::" || s == "*"
}

// normalizeBindAddr normalizes an address with optional interface binding to
// a standard listen address (ip:port). If an interface is specified, it resolves
// the interface's IP.
func normalizeBindAddr(raw string, defaultPort int) (string, error) {
	cfg, err := ParseBindAddr(raw, defaultPort)
	if err != nil {
		return "", err
	}
	return cfg.Address, nil
}

// interfaceForAddr detects if an address string includes an interface binding
// and returns the interface name (empty if none).
func interfaceForAddr(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		return ""
	}
	if host != "" && !isValidIP(host) && !isWildcardHost(host) {
		if IsInterfaceName(host) {
			return host
		}
	}
	return ""
}
