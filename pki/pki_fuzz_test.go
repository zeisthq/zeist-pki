package pki

import (
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func FuzzParsePEM(f *testing.F) {
	f.Add([]byte("not PEM"), []byte("not PEM"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"), []byte("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n"))
	f.Fuzz(func(t *testing.T, certificatePEM, privateKeyPEM []byte) {
		_, _ = ParseCertificatePEM(certificatePEM)
		_, _ = ParseCertificatesPEM(certificatePEM)
		_, _ = ParsePrivateKeyPEM(privateKeyPEM)
		_, _, _ = ParseKeyPairPEM(certificatePEM, privateKeyPEM)
	})
}

func FuzzCanonicalSANs(f *testing.F) {
	f.Add("Example.TEST.", "10.0.0.1")
	f.Add("*.example.test", "2001:db8::1")
	f.Add("bad_name", "not-an-ip")
	f.Fuzz(func(t *testing.T, dnsName, ipText string) {
		var ips []net.IP
		if ip := net.ParseIP(ipText); ip != nil {
			ips = []net.IP{ip}
		}
		_, _ = CanonicalSANs([]string{dnsName}, ips)
	})
}

func FuzzCertificateChainValidation(f *testing.F) {
	now := time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC)
	root, err := IssueRoot(RootOptions{CommonName: "fuzz root", Now: now})
	if err != nil {
		f.Fatalf("issue root: %v", err)
	}
	leaf, err := IssueLeaf(root, LeafOptions{
		CommonName: "fuzz service", Profile: ProfileServer,
		DNSNames: []string{"fuzz.example.test"}, Now: now,
	})
	if err != nil {
		f.Fatalf("issue leaf: %v", err)
	}
	f.Add(root.CertificatePEM, root.PrivateKeyPEM, leaf.CertificatePEM, leaf.PrivateKeyPEM)

	f.Fuzz(func(t *testing.T, rootCertificatePEM, rootPrivateKeyPEM, leafCertificatePEM, leafPrivateKeyPEM []byte) {
		parsedRoot, err := ParseRootPEM(rootCertificatePEM, rootPrivateKeyPEM)
		if err != nil {
			return
		}
		parsedLeaf, err := ParseLeafPEM(leafCertificatePEM, leafPrivateKeyPEM)
		if err != nil {
			return
		}
		_ = ValidateLeaf(parsedLeaf, []*x509.Certificate{parsedRoot.Certificate}, ProfileServer, now)
	})
}
