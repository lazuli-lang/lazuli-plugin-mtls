package mtlsplugin

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"lazuli.dev/runtime/lazuli"
	lazulimtls "lazuli.dev/runtime/lazuli/mtls"
	"os"
	"sync"
	"time"
)

func init() {
	lazuli.RegisterAdapter("@plugin/mtls", NewFromEnv())
}

type Adapter struct {
	path  string
	spire bool
	once  sync.Once
	roots *x509.CertPool
	err   error
}

var _ lazulimtls.Verifier = (*Adapter)(nil)

func NewFromEnv() *Adapter {
	if os.Getenv("MTLS_VENDOR") == "spire" {
		return &Adapter{spire: true}
	}
	return NewCABundle(os.Getenv("MTLS_CA_BUNDLE_PATH"))
}
func NewCABundle(path string) *Adapter {
	return &Adapter{path: path}
}
func (a *Adapter) Verify(_ context.Context, cert *x509.Certificate, chain [][]*x509.Certificate) (lazulimtls.Identity, error) {
	if a.spire {
		return lazulimtls.Identity{}, fmt.Errorf("%w: SPIRE flavor not implemented", lazulimtls.ErrVerifierUnavailable)
	}
	if cert == nil {
		return lazulimtls.Identity{}, lazulimtls.ErrUntrustedCA
	}
	roots, err := a.loadRoots()
	if err != nil {
		return lazulimtls.Identity{}, err
	}
	inter := x509.NewCertPool()
	for _, certs := range chain {
		for _, c := range certs {
			if c != nil && !c.Equal(cert) {
				inter.AddCert(c)
			}
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: time.Now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return lazulimtls.Identity{}, mapVerifyErr(err)
	}
	return lazulimtls.Identity{Subject: subject(cert), Issuer: cert.Issuer.String()}, nil
}
func (a *Adapter) Close() error { return nil }
func (a *Adapter) loadRoots() (*x509.CertPool, error) {
	a.once.Do(func() {
		if a.path == "" {
			a.err = lazulimtls.ErrVerifierUnavailable
			return
		}
		pemBytes, err := os.ReadFile(a.path)
		if err != nil {
			a.err = fmt.Errorf("%w: %v", lazulimtls.ErrVerifierUnavailable, err)
			return
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			a.err = fmt.Errorf("%w: empty CA bundle", lazulimtls.ErrUntrustedCA)
			return
		}
		a.roots = pool
	})
	return a.roots, a.err
}
func mapVerifyErr(err error) error {
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return lazulimtls.ErrCertExpired
	}
	return lazulimtls.ErrUntrustedCA
}
func subject(cert *x509.Certificate) string {
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return cert.Subject.CommonName
}
