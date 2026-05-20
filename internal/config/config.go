package config

import (
	"crypto/tls"
	"sync/atomic"
)

const ASCII = `
 ________  ________  ________  _______   ________  ________  ________  ___  ___
|\   ____\|\   __  \|\   ____\|\  ___ \ |\   __  \|\   __  \|\   ____\|\  \|\  \
\ \  \___|\ \  \|\  \ \  \___|\ \   __/|\ \  \|\  \ \  \|\  \ \  \___|\ \  \\\  \
 \ \  \  __\ \  \\\  \ \_____  \ \  \_|/_\ \   __  \ \   _  _\ \  \    \ \   __  \
  \ \  \|\  \ \  \\\  \|____|\  \ \  \_|\ \ \  \ \  \ \  \\  \\ \  \____\ \  \ \  \
   \ \_______\ \_______\____\_\  \ \_______\ \__\ \__\ \__\\ _\\ \_______\ \__\ \__\
    \|_______|\|_______|\_________\|_______|\|__|\|__|\|__|\|__|\|_______|\|__|\|__|
                       \|_________|

`

const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0"

const VERSION = "v1.0.0"

var TLSConfig = &tls.Config{
	MinVersion: tls.VersionTLS12,
	CipherSuites: []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	},
	CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	NextProtos:       []string{"http/1.1"},
}

var (
	Count     atomic.Uint32
	OutputDir = "."
)
