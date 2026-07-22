package relay

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// IsPublicIP reports whether ip is a globally routable unicast address.
// Everything else (loopback, RFC1918, link-local incl. the 169.254.169.254
// metadata endpoint, CGNAT, ULA, multicast, unspecified, 192.0.0.0/24) is
// refused so a registered origin can never be used to reach internal
// infrastructure (OWASP SSRF prevention).
func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1]&0xc0 == 64 { // 100.64.0.0/10 (CGNAT)
			return false
		}
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0 { // 192.0.0.0/24 (IETF)
			return false
		}
		if (ip4[0] == 198 && ip4[1]&0xfe == 18) || // 198.18.0.0/15 (benchmarking)
			(ip4[0] == 192 && ip4[1] == 88 && ip4[2] == 99) || // 192.88.99.0/24
			ip4[0]&0xf0 == 0xf0 { // 240.0.0.0/4, including limited broadcast
			return false
		}
		return true
	}
	ip16 := ip.To16()
	if (ip16[0] == 0x20 && ip16[1] == 0x02) || // 2002::/16 (6to4)
		bytes.Equal(ip16[:12], []byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}) { // NAT64
		return false
	}
	return true
}

// SafeDialContext resolves addr, filters non-public IPs, and dials the first
// vetted IP directly. Dialing the vetted IP (not the hostname) pins the
// resolution for this connection, defeating DNS-rebinding races.
func SafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	var dialErr error
	for _, ip := range ips {
		if IsPublicIP(ip) {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			dialErr = err
		}
	}
	if dialErr != nil {
		return nil, fmt.Errorf("could not dial %q: %w", host, dialErr)
	}
	return nil, fmt.Errorf("refusing to dial %q: no public IP", host)
}

// NewOriginClient is the client for all relay->origin traffic. Redirects are
// never followed (an open-redirect on a customer site must not become an
// allowlist bypass); the 3xx is passed through to the caller as-is.
func NewOriginClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:         SafeDialContext,
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConnsPerHost: 4,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
