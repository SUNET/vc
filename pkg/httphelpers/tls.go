package httphelpers

import (
	"context"
	"crypto/tls"
	"github.com/SUNET/vc/pkg/logger"
)

type tlsHandler struct {
	client *Client
	log    *logger.Log
}

// Standard returns a standard tls.Config object
func (t *tlsHandler) Standard(ctx context.Context) *tls.Config {
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
	}

	return tlsConfig
}
