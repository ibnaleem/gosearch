package config

import (
	"net"
	"net/http"
	"time"
)

// NewHTTPClient returns the client used for outgoing requests: a 30s timeout,
// the shared TLS config and the proxy from the environment. Each caller gets
// its own client, so one source's connection pool doesn't affect another's.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: TLSConfig,
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}
