// Package v1 defines the dependency-free wire contract between zeist-pki and
// certificate consumers. It contains no Kubernetes client types.
package v1

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DomainAnnotation           = "pki.zeist.io/domain"
	GenerationAnnotation       = "pki.zeist.io/generation"
	OperationAnnotation        = "pki.zeist.io/operation-id"
	LeafFingerprintAnnotation  = "pki.zeist.io/leaf-fingerprint"
	TrustFingerprintAnnotation = "pki.zeist.io/trust-bundle-fingerprint"
	AcknowledgementAnnotation  = "pki.zeist.io/acknowledgement"

	DefaultLeaseDuration = 30 * time.Second
	DefaultRenewInterval = 10 * time.Second
)

// Material identifies one published consumer generation without exposing PEM.
type Material struct {
	Generation       uint64 `json:"generation"`
	LeafFingerprint  string `json:"leafFingerprint"`
	TrustFingerprint string `json:"trustFingerprint"`
}

// Acknowledgement is the credential-free value stored in a consumer Lease.
type Acknowledgement struct {
	Generation       uint64 `json:"generation"`
	LeafFingerprint  string `json:"leafFingerprint"`
	TrustFingerprint string `json:"trustFingerprint"`
}

// PodTargetID returns the target identity used for one exact consumer Pod UID.
func PodTargetID(role, podUID string) (string, error) {
	role = strings.TrimSpace(role)
	podUID = strings.TrimSpace(podUID)
	if role != "server" && role != "client" {
		return "", fmt.Errorf("consumer role must be server or client")
	}
	if podUID == "" {
		return "", fmt.Errorf("consumer Pod UID is required")
	}
	return role + ":" + podUID, nil
}

// AcknowledgementLeaseName returns the stable Lease name for one target.
func AcknowledgementLeaseName(domain, targetID string) string {
	sum := sha256.Sum256([]byte(targetID))
	return "zeist-pki-ack-" + domain + "-" + hex.EncodeToString(sum[:])[:16]
}

// EncodeAcknowledgement produces the exact JSON annotation payload.
func EncodeAcknowledgement(value Acknowledgement) (string, error) {
	if err := validateAcknowledgement(value); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// DecodeAcknowledgement parses and validates an exact JSON annotation payload.
func DecodeAcknowledgement(encoded string) (Acknowledgement, error) {
	var value Acknowledgement
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return Acknowledgement{}, fmt.Errorf("decode acknowledgement: %w", err)
	}
	var additional any
	if err := decoder.Decode(&additional); err != io.EOF {
		if err == nil {
			return Acknowledgement{}, fmt.Errorf("decode acknowledgement: multiple values are not supported")
		}
		return Acknowledgement{}, fmt.Errorf("decode acknowledgement: %w", err)
	}
	if err := validateAcknowledgement(value); err != nil {
		return Acknowledgement{}, err
	}
	return value, nil
}

func validateAcknowledgement(value Acknowledgement) error {
	if value.Generation == 0 {
		return fmt.Errorf("acknowledgement generation must be positive")
	}
	if !validFingerprint(value.LeafFingerprint) || !validFingerprint(value.TrustFingerprint) {
		return fmt.Errorf("acknowledgement fingerprints must be canonical SHA-256 values")
	}
	return nil
}

// MaterialFromAnnotations parses the managed Secret publication annotations.
func MaterialFromAnnotations(annotations map[string]string) (Material, error) {
	generation, err := strconv.ParseUint(annotations[GenerationAnnotation], 10, 64)
	if err != nil || generation == 0 || annotations[GenerationAnnotation] != strconv.FormatUint(generation, 10) {
		return Material{}, fmt.Errorf("publication generation annotation is invalid")
	}
	material := Material{
		Generation:       generation,
		LeafFingerprint:  annotations[LeafFingerprintAnnotation],
		TrustFingerprint: annotations[TrustFingerprintAnnotation],
	}
	if !validFingerprint(material.LeafFingerprint) || !validFingerprint(material.TrustFingerprint) {
		return Material{}, fmt.Errorf("publication fingerprint annotations are invalid")
	}
	return material, nil
}

// FingerprintsFromPEM returns the leaf and canonical trust-bundle fingerprints.
func FingerprintsFromPEM(certificatePEM, trustPEM []byte) (leaf, trust string, err error) {
	certificates, err := parseCertificates(certificatePEM)
	if err != nil {
		return "", "", fmt.Errorf("parse leaf certificate: %w", err)
	}
	if len(certificates) != 1 {
		return "", "", fmt.Errorf("leaf certificate PEM must contain exactly one certificate")
	}
	roots, err := parseCertificates(trustPEM)
	if err != nil {
		return "", "", fmt.Errorf("parse trust bundle: %w", err)
	}
	return CertificateFingerprint(certificates[0]), BundleFingerprint(roots), nil
}

// CertificateFingerprint returns the canonical SHA-256 certificate identity.
func CertificateFingerprint(certificate *x509.Certificate) string {
	if certificate == nil {
		return ""
	}
	sum := sha256.Sum256(certificate.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BundleFingerprint returns a canonical order-independent trust identity.
func BundleFingerprint(certificates []*x509.Certificate) string {
	raw := make([][]byte, 0, len(certificates))
	for _, certificate := range certificates {
		if certificate != nil {
			raw = append(raw, certificate.Raw)
		}
	}
	sort.Slice(raw, func(first, second int) bool { return bytes.Compare(raw[first], raw[second]) < 0 })
	digest := sha256.New()
	for _, certificate := range raw {
		_, _ = digest.Write(certificate)
		_, _ = digest.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("invalid PEM data")
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
		data = rest
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("certificate PEM is empty")
	}
	return certificates, nil
}

func validFingerprint(value string) bool {
	encoded, found := strings.CutPrefix(value, "sha256:")
	if !found || len(encoded) != sha256.Size*2 || encoded != strings.ToLower(encoded) {
		return false
	}
	_, err := hex.DecodeString(encoded)
	return err == nil
}
