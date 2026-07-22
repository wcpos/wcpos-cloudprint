package relay

import (
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
	for _, ip := range ips {
		if IsPublicIP(ip) {
			return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
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
