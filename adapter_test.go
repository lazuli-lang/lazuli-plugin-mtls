package mtlsplugin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	lazulimtls "lazuli.dev/runtime/lazuli/mtls"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCABundleVerifier(t *testing.T) {
	caCert, caKey := testCert(t, "test-ca", nil, nil, true)
	leaf, _ := testCert(t, "service-a", caCert, caKey, false)
	path := writeBundle(t, caCert)

	if _, err := NewCABundle(path).Verify(context.Background(), leaf, nil); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	untrustedCA, untrustedKey := testCert(t, "untrusted-ca", nil, nil, true)
	untrustedLeaf, _ := testCert(t, "service-b", untrustedCA, untrustedKey, false)
	if _, err := NewCABundle(path).Verify(context.Background(), untrustedLeaf, nil); !errors.Is(err, lazulimtls.ErrUntrustedCA) {
		t.Fatalf("Verify() error = %v, want %v", err, lazulimtls.ErrUntrustedCA)
	}
}
func testCert(t *testing.T, cn string, parent *x509.Certificate, signer *rsa.PrivateKey, ca bool) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if ca {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tmpl.BasicConstraintsValid = true
		tmpl.IsCA = true
		parent = tmpl
		signer = key
	} else {
		tmpl.DNSNames = []string{cn + ".local"}
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}
func writeBundle(t *testing.T, cert *x509.Certificate) string {
	path := filepath.Join(t.TempDir(), "ca.pem")
	err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600)
	if err != nil {
		t.Fatal(err)
	}
	return path
}
