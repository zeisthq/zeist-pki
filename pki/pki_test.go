package pki

import (
	"crypto/x509"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2042, time.March, 4, 5, 6, 7, 0, time.UTC)

func TestIssueRootAndServerLeaf(t *testing.T) {
	root := mustRoot(t, "zeist runner root")
	if got, want := root.Certificate.NotBefore, testNow.Add(-DefaultNotBeforeBackdate); !got.Equal(want) {
		t.Fatalf("root NotBefore = %s, want %s", got, want)
	}
	if got, want := root.Certificate.NotAfter, testNow.Add(DefaultRootValidity); !got.Equal(want) {
		t.Fatalf("root NotAfter = %s, want %s", got, want)
	}
	if err := ValidateRoot(root, testNow); err != nil {
		t.Fatalf("ValidateRoot() error = %v", err)
	}

	leaf, err := IssueLeaf(root, LeafOptions{
		CommonName: "zeistd",
		Profile:    ProfileServer,
		DNSNames:   []string{"ZEISTD.ZEIST-SYSTEM.SVC.", "zeistd.zeist-system.svc"},
		IPAddresses: []net.IP{
			net.ParseIP("10.20.30.40"),
			net.ParseIP("2001:db8::1"),
			net.ParseIP("10.20.30.40"),
		},
		Now: testNow,
	})
	if err != nil {
		t.Fatalf("IssueLeaf() error = %v", err)
	}
	if got, want := leaf.Certificate.DNSNames, []string{"zeistd.zeist-system.svc"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("DNSNames = %#v, want %#v", got, want)
	}
	if got, want := len(leaf.Certificate.IPAddresses), 2; got != want {
		t.Fatalf("IPAddresses length = %d, want %d", got, want)
	}
	if got, want := leaf.Certificate.NotAfter, testNow.Add(DefaultLeafValidity); !got.Equal(want) {
		t.Fatalf("leaf NotAfter = %s, want %s", got, want)
	}
	if err := ValidateLeaf(leaf, []*x509.Certificate{root.Certificate}, ProfileServer, testNow); err != nil {
		t.Fatalf("ValidateLeaf() error = %v", err)
	}
	chain, err := EncodeCertificatesPEM(leaf.Certificate, root.Certificate)
	if err != nil {
		t.Fatalf("EncodeCertificatesPEM() error = %v", err)
	}
	if certificates, err := ParseCertificatesPEM(chain); err != nil || len(certificates) != 2 {
		t.Fatalf("ParseCertificatesPEM() = %d certificates, %v", len(certificates), err)
	}
}

func TestProfilesHaveStrictSANRequirements(t *testing.T) {
	root := mustRoot(t, "zeist profile root")
	_, err := IssueLeaf(root, LeafOptions{CommonName: "webhook", Profile: ProfileWebhook, Now: testNow})
	if err == nil || !strings.Contains(err.Error(), "DNS SAN") {
		t.Fatalf("webhook without DNS SAN error = %v, want DNS SAN error", err)
	}
	_, err = IssueLeaf(root, LeafOptions{
		CommonName:  "webhook",
		Profile:     ProfileWebhook,
		DNSNames:    []string{"webhook.zeist-system.svc"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
		Now:         testNow,
	})
	if err == nil || !strings.Contains(err.Error(), "does not permit IP") {
		t.Fatalf("webhook with IP SAN error = %v, want IP SAN error", err)
	}
	_, err = IssueLeaf(root, LeafOptions{CommonName: "server", Profile: ProfileServer, Now: testNow})
	if err == nil || !strings.Contains(err.Error(), "requires at least") {
		t.Fatalf("server without SAN error = %v, want required SAN error", err)
	}
	if _, err := IssueLeaf(root, LeafOptions{
		CommonName:  "node",
		Profile:     ProfileServer,
		IPAddresses: []net.IP{net.ParseIP("192.0.2.10")},
		Now:         testNow,
	}); err != nil {
		t.Fatalf("IssueLeaf(server with IP-only SAN) error = %v", err)
	}
	client, err := IssueLeaf(root, LeafOptions{CommonName: "manager", Profile: ProfileClient, Now: testNow})
	if err != nil {
		t.Fatalf("IssueLeaf(client without SAN) error = %v", err)
	}
	if len(client.Certificate.DNSNames) != 0 || len(client.Certificate.IPAddresses) != 0 {
		t.Fatalf("client unexpectedly has SANs: DNS=%v IP=%v", client.Certificate.DNSNames, client.Certificate.IPAddresses)
	}
	if err := ValidateLeaf(client, []*x509.Certificate{root.Certificate}, ProfileClient, testNow); err != nil {
		t.Fatalf("ValidateLeaf(client) error = %v", err)
	}
}

func TestLeafExpiryIsBoundedByRoot(t *testing.T) {
	root, err := IssueRoot(RootOptions{CommonName: "short root", Validity: time.Hour, Now: testNow})
	if err != nil {
		t.Fatalf("IssueRoot() error = %v", err)
	}
	leaf, err := IssueLeaf(root, LeafOptions{
		CommonName: "server",
		Profile:    ProfileServer,
		DNSNames:   []string{"server.example.test"},
		Now:        testNow,
	})
	if err != nil {
		t.Fatalf("IssueLeaf() error = %v", err)
	}
	if !leaf.Certificate.NotAfter.Equal(root.Certificate.NotAfter) {
		t.Fatalf("leaf expiry %s is not capped by root expiry %s", leaf.Certificate.NotAfter, root.Certificate.NotAfter)
	}
}

func TestCanonicalSANs(t *testing.T) {
	sans, err := CanonicalSANs(
		[]string{" B.Example.TEST. ", "a.example.test", "*.Example.Test", "a.example.test"},
		[]net.IP{net.ParseIP("2001:0db8:0:0:0:0:0:1"), net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.1")},
	)
	if err != nil {
		t.Fatalf("CanonicalSANs() error = %v", err)
	}
	if got, want := sans.DNSNames, []string{"*.example.test", "a.example.test", "b.example.test"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("DNSNames = %#v, want %#v", got, want)
	}
	gotIPs := []string{sans.IPAddresses[0].String(), sans.IPAddresses[1].String()}
	if want := []string{"10.0.0.1", "2001:db8::1"}; !reflect.DeepEqual(gotIPs, want) {
		t.Fatalf("IPAddresses = %#v, want %#v", gotIPs, want)
	}
	for _, invalid := range []string{"", "127.0.0.1", "bad_name.example", "-bad.example", "example..test"} {
		if _, err := CanonicalSANs([]string{invalid}, nil); !errors.Is(err, ErrInvalidSAN) {
			t.Errorf("CanonicalSANs(%q) error = %v, want ErrInvalidSAN", invalid, err)
		}
	}
}

func TestPEMParsingIsStrictAndRoundTrips(t *testing.T) {
	root := mustRoot(t, "zeist parse root")
	parsed, err := ParseRootPEM(root.CertificatePEM, root.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("ParseRootPEM() error = %v", err)
	}
	if got, want := parsed.Fingerprint(), root.Fingerprint(); got != want {
		t.Fatalf("parsed root fingerprint = %q, want %q", got, want)
	}
	if _, err := ParseCertificatePEM(append(append([]byte(nil), root.CertificatePEM...), []byte("trailing")...)); err == nil {
		t.Fatal("ParseCertificatePEM() accepted trailing content")
	}
	if _, err := ParsePrivateKeyPEM(append(append([]byte(nil), root.PrivateKeyPEM...), root.PrivateKeyPEM...)); err == nil {
		t.Fatal("ParsePrivateKeyPEM() accepted a second key")
	}
	other := mustRoot(t, "other root")
	if _, _, err := ParseKeyPairPEM(root.CertificatePEM, other.PrivateKeyPEM); err == nil {
		t.Fatal("ParseKeyPairPEM() accepted mismatched key material")
	}
	if fingerprint := root.Fingerprint(); len(fingerprint) != 64 || fingerprint != strings.ToLower(fingerprint) {
		t.Fatalf("fingerprint = %q, want 64 lower-case hexadecimal characters", fingerprint)
	}
	if fingerprint := CertificateFingerprint(nil); fingerprint != "" {
		t.Fatalf("CertificateFingerprint(nil) = %q, want empty", fingerprint)
	}
}

func TestLeafValidationRejectsWrongProfileAndRoot(t *testing.T) {
	root := mustRoot(t, "zeist validation root")
	leaf, err := IssueLeaf(root, LeafOptions{
		CommonName: "server",
		Profile:    ProfileServer,
		DNSNames:   []string{"server.example.test"},
		Now:        testNow,
	})
	if err != nil {
		t.Fatalf("IssueLeaf() error = %v", err)
	}
	if err := ValidateLeaf(leaf, []*x509.Certificate{root.Certificate}, ProfileClient, testNow); err == nil {
		t.Fatal("ValidateLeaf() accepted server leaf as client leaf")
	}
	other := mustRoot(t, "other validation root")
	if err := ValidateLeaf(leaf, []*x509.Certificate{other.Certificate}, ProfileServer, testNow); err == nil {
		t.Fatal("ValidateLeaf() accepted an unrelated root")
	}
}

func TestValidateRootUsesCurrentTimeWhenUnset(t *testing.T) {
	past := time.Now().UTC().Add(-2 * time.Hour)
	root, err := IssueRoot(RootOptions{CommonName: "expired root", Validity: time.Hour, Now: past})
	if err != nil {
		t.Fatalf("IssueRoot() error = %v", err)
	}
	if _, err := ParseRootPEM(root.CertificatePEM, root.PrivateKeyPEM); err != nil {
		t.Fatalf("ParseRootPEM() should allow inspection of expired material: %v", err)
	}
	if err := ValidateRoot(root, time.Time{}); err == nil {
		t.Fatal("ValidateRoot() with zero time accepted expired root")
	}
}

func mustRoot(t *testing.T, commonName string) *RootMaterial {
	t.Helper()
	root, err := IssueRoot(RootOptions{CommonName: commonName, Now: testNow})
	if err != nil {
		t.Fatalf("IssueRoot() error = %v", err)
	}
	return root
}
