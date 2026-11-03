package config

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// NewHTTPClient returns the client used for outgoing requests: a 30s timeout,
// the shared TLS config and the proxy from the environment. Each caller gets
// its own client, so one source's connection pool doesn't affect another's.
func NewHTTPClient() *http.Client {
	return newHTTPClient(nil)
}

// NewPublicHTTPClient is NewHTTPClient for requests aimed at third-party
// sites, where a redirect or DNS answer could point back at the local
// machine or network. It refuses to connect to non-public addresses.
func NewPublicHTTPClient() *http.Client {
	// with a proxy the proxy does the dialing, so the dial-time check would
	// only block a local proxy (e.g. Burp) and never see the target address
	if proxy, _ := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}}); proxy != nil {
		return newHTTPClient(nil)
	}

	return newHTTPClient(refusePrivateAddress)
}

func newHTTPClient(control func(network, address string, conn syscall.RawConn) error) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: TLSConfig,
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				Control:   control,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// refusePrivateAddress runs on the resolved IP just before connecting, so it
// also covers redirects and DNS rebinding.
func refusePrivateAddress(_, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}

	addr := addrPort.Addr().Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return fmt.Errorf("refusing to connect to non-public address %s", addr)
	}

	return nil
}
