package v1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestAcknowledgementRoundTrip(t *testing.T) {
	value := Acknowledgement{Generation: 7, LeafFingerprint: fingerprint("leaf"), TrustFingerprint: fingerprint("trust")}
	encoded, err := EncodeAcknowledgement(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAcknowledgement(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != value {
		t.Fatalf("decoded = %#v, want %#v", decoded, value)
	}
}

func TestAcknowledgementRejectsNonCanonicalFingerprints(t *testing.T) {
	value := Acknowledgement{Generation: 1, LeafFingerprint: fingerprint("leaf"), TrustFingerprint: fingerprint("trust")}
	value.LeafFingerprint = "sha256:" + strings.ToUpper(strings.TrimPrefix(value.LeafFingerprint, "sha256:"))
	if _, err := EncodeAcknowledgement(value); err == nil {
		t.Fatal("EncodeAcknowledgement accepted an uppercase fingerprint")
	}
}

func TestMaterialMatchesPEMAndAnnotations(t *testing.T) {
	leaf := testCertificate(t, "leaf")
	rootA := testCertificate(t, "root-a")
	rootB := testCertificate(t, "root-b")
	leafFingerprint, trustFingerprint, err := FingerprintsFromPEM(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootB.Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootA.Raw})...),
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := MaterialFromAnnotations(map[string]string{
		GenerationAnnotation: "9", LeafFingerprintAnnotation: leafFingerprint, TrustFingerprintAnnotation: trustFingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if material.Generation != 9 || material.LeafFingerprint != CertificateFingerprint(leaf) || material.TrustFingerprint != BundleFingerprint([]*x509.Certificate{rootA, rootB}) {
		t.Fatalf("material = %#v", material)
	}
}

func TestPodTargetAndLeaseNamesAreStable(t *testing.T) {
	target, err := PodTargetID("server", "pod-uid")
	if err != nil {
		t.Fatal(err)
	}
	if target != "server:pod-uid" {
		t.Fatalf("target = %q", target)
	}
	if got, want := AcknowledgementLeaseName("service", target), AcknowledgementLeaseName("service", target); got != want {
		t.Fatalf("Lease name = %q, want %q", got, want)
	}
}

func fingerprint(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func testCertificate(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(int64(len(name) + 1)), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
