package security

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"

	"github.com/arencloud/hecate/internal/config"
)

func BuildServerTLS(t config.TLS) (*tls.Config, error) {
	if len(t.CertFiles) == 0 || len(t.KeyFiles) == 0 || len(t.CertFiles) != len(t.KeyFiles) {
		// No TLS configured
		return &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1", "h3"}}, nil
	}
	certs := make([]tls.Certificate, 0, len(t.CertFiles))
	for i := range t.CertFiles {
		cert, err := tls.LoadX509KeyPair(t.CertFiles[i], t.KeyFiles[i])
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: certs,
		NextProtos:   []string{"h2", "http/1.1", "h3"},
	}
	if t.RequireClientCert || t.ClientCAFile != "" {
		pool := x509.NewCertPool()
		if t.ClientCAFile != "" {
			b, err := os.ReadFile(t.ClientCAFile)
			if err != nil {
				return nil, err
			}
			if ok := pool.AppendCertsFromPEM(b); !ok {
				return nil, ErrBadCA
			}
		}
		tlsCfg.ClientCAs = pool
		if t.RequireClientCert {
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	return tlsCfg, nil
}

var ErrBadCA = errors.New("invalid client CA bundle")
