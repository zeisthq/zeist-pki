// Package pki provides the small, portable certificate primitives used by
// zeist-pki. It deliberately only supports the private-root model used by the
// rotation engine: ECDSA P-256 roots and directly-issued leaf certificates.
package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	// DefaultRootValidity is the default lifetime for a private trust root.
	DefaultRootValidity = 365 * 24 * time.Hour
	// DefaultLeafValidity is the default lifetime for a leaf certificate.
	DefaultLeafValidity = 90 * 24 * time.Hour
	// DefaultNotBeforeBackdate tolerates small clock skew when new material is
	// activated across a fleet.
	DefaultNotBeforeBackdate = 5 * time.Minute
)

// Profile defines the intended TLS use of a leaf certificate.
type Profile string

const (
	// ProfileWebhook is a DNS-only TLS server certificate for an admission
	// webhook. It has the ServerAuth extended key usage.
	ProfileWebhook Profile = "webhook"
	// ProfileServer is a TLS server certificate with one or more DNS or IP SANs.
	ProfileServer Profile = "server"
	// ProfileClient is an mTLS client certificate. SANs are optional, but when
	// supplied they use the same canonical form as server SANs.
	ProfileClient Profile = "client"
)

var (
	// ErrInvalidProfile indicates that a caller selected an unsupported leaf
	// profile.
	ErrInvalidProfile = errors.New("invalid certificate profile")
	// ErrInvalidSAN indicates that a DNS or IP subject alternative name is not
	// suitable for a deterministic service identity.
	ErrInvalidSAN = errors.New("invalid subject alternative name")
)

// SANs is a deterministic, canonical set of DNS and IP subject alternative
// names. DNS names are lower-case, have no trailing dot, and are sorted.
// IP addresses use their shortest canonical form and are sorted by text form.
type SANs struct {
	DNSNames    []string
	IPAddresses []net.IP
}

// RootOptions controls a newly issued self-signed private root.
type RootOptions struct {
	// Subject is copied into the root certificate. Its CommonName must be set,
	// either here or through CommonName.
	Subject pkix.Name
	// CommonName is a convenient alternative to Subject.CommonName. Supplying
	// both with different values is rejected.
	CommonName string
	// Validity defaults to DefaultRootValidity when zero.
	Validity time.Duration
	// Now defaults to the current UTC time when zero. Issuance normalizes it to
	// whole seconds so persisted material is deterministic for a supplied clock.
	Now time.Time
}

// LeafOptions controls a leaf issued directly by a private root.
type LeafOptions struct {
	// Subject is copied into the leaf certificate. Its CommonName must be set,
	// either here or through CommonName.
	Subject pkix.Name
	// CommonName is a convenient alternative to Subject.CommonName. Supplying
	// both with different values is rejected.
	CommonName  string
	Profile     Profile
	DNSNames    []string
	IPAddresses []net.IP
	// Validity defaults to DefaultLeafValidity when zero. The final lifetime is
	// always capped at the issuer root's NotAfter time.
	Validity time.Duration
	// Now defaults to the current UTC time when zero.
	Now time.Time
}

// RootMaterial contains the private material required to issue leaves. The
// PEM fields contain exactly one certificate and one unencrypted private key.
// Callers must protect PrivateKeyPEM and must never publish it to consumers.
type RootMaterial struct {
	Certificate    *x509.Certificate
	PrivateKey     *ecdsa.PrivateKey
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

// LeafMaterial contains a leaf certificate and its private key. Its
// CertificatePEM contains the leaf only; callers can build a chain or trust
// bundle explicitly with EncodeCertificatesPEM.
type LeafMaterial struct {
	Certificate    *x509.Certificate
	PrivateKey     *ecdsa.PrivateKey
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

// IssueRoot creates a self-signed ECDSA P-256 private root.
func IssueRoot(options RootOptions) (*RootMaterial, error) {
	subject, err := canonicalSubject(options.Subject, options.CommonName)
	if err != nil {
		return nil, err
	}
	validity, err := validityOrDefault(options.Validity, DefaultRootValidity)
	if err != nil {
		return nil, fmt.Errorf("root validity: %w", err)
	}
	now := normalizedTime(options.Now)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	keyID, err := publicKeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-DefaultNotBeforeBackdate),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          keyID,
		AuthorityKeyId:        keyID,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create root certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated root certificate: %w", err)
	}
	material, err := newRootMaterial(certificate, key)
	if err != nil {
		return nil, err
	}
	if err := ValidateRoot(material, now); err != nil {
		return nil, fmt.Errorf("validate generated root: %w", err)
	}
	return material, nil
}

// IssueLeaf creates an ECDSA P-256 leaf issued directly by issuer. The issuer
// must be valid at the requested issuance time.
func IssueLeaf(issuer *RootMaterial, options LeafOptions) (*LeafMaterial, error) {
	if issuer == nil {
		return nil, errors.New("issuer is required")
	}
	subject, err := canonicalSubject(options.Subject, options.CommonName)
	if err != nil {
		return nil, err
	}
	profile, err := profileSpec(options.Profile)
	if err != nil {
		return nil, err
	}
	sans, err := CanonicalSANs(options.DNSNames, options.IPAddresses)
	if err != nil {
		return nil, err
	}
	if err := profile.validateSANs(sans); err != nil {
		return nil, err
	}
	validity, err := validityOrDefault(options.Validity, DefaultLeafValidity)
	if err != nil {
		return nil, fmt.Errorf("leaf validity: %w", err)
	}
	now := normalizedTime(options.Now)
	if err := ValidateRoot(issuer, now); err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	keyID, err := publicKeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(validity)
	if notAfter.After(issuer.Certificate.NotAfter) {
		notAfter = issuer.Certificate.NotAfter
	}
	if !notAfter.After(now) {
		return nil, errors.New("issuer expires before the leaf can be issued")
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-DefaultNotBeforeBackdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{profile.usage},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              append([]string(nil), sans.DNSNames...),
		IPAddresses:           cloneIPs(sans.IPAddresses),
		SubjectKeyId:          keyID,
		AuthorityKeyId:        append([]byte(nil), issuer.Certificate.SubjectKeyId...),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.Certificate, &key.PublicKey, issuer.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated leaf certificate: %w", err)
	}
	material, err := newLeafMaterial(certificate, key)
	if err != nil {
		return nil, err
	}
	if err := ValidateLeaf(material, []*x509.Certificate{issuer.Certificate}, options.Profile, now); err != nil {
		return nil, fmt.Errorf("validate generated leaf: %w", err)
	}
	return material, nil
}

// CanonicalSANs validates, de-duplicates, and sorts DNS and IP SANs. DNS
// names are restricted to ASCII DNS labels (plus a leftmost wildcard), which
// keeps service identities unambiguous without an IDNA dependency.
func CanonicalSANs(dnsNames []string, ipAddresses []net.IP) (SANs, error) {
	dnsSet := make(map[string]struct{}, len(dnsNames))
	for _, name := range dnsNames {
		canonical, err := canonicalDNSName(name)
		if err != nil {
			return SANs{}, err
		}
		dnsSet[canonical] = struct{}{}
	}
	dns := make([]string, 0, len(dnsSet))
	for name := range dnsSet {
		dns = append(dns, name)
	}
	sort.Strings(dns)

	ipSet := make(map[string]net.IP, len(ipAddresses))
	for _, ip := range ipAddresses {
		canonical, err := canonicalIP(ip)
		if err != nil {
			return SANs{}, err
		}
		ipSet[canonical.String()] = net.IP(append([]byte(nil), canonical.AsSlice()...))
	}
	ipText := make([]string, 0, len(ipSet))
	for text := range ipSet {
		ipText = append(ipText, text)
	}
	sort.Strings(ipText)
	ips := make([]net.IP, 0, len(ipText))
	for _, text := range ipText {
		ips = append(ips, append(net.IP(nil), ipSet[text]...))
	}
	return SANs{DNSNames: dns, IPAddresses: ips}, nil
}

// ParseRootPEM parses a root certificate and matching ECDSA private key. It
// verifies structural root constraints but does not apply a clock check; use
// ValidateRoot for an operational validity check.
func ParseRootPEM(certificatePEM, privateKeyPEM []byte) (*RootMaterial, error) {
	certificate, key, err := ParseKeyPairPEM(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, err
	}
	material, err := newRootMaterial(certificate, key)
	if err != nil {
		return nil, err
	}
	if err := validateRootCertificate(certificate, time.Time{}); err != nil {
		return nil, err
	}
	if err := validateRootKeyMaterial(material); err != nil {
		return nil, err
	}
	return material, nil
}

// ParseLeafPEM parses a leaf certificate and matching ECDSA private key. It
// does not validate a profile, trust chain, or clock; use ValidateLeaf for
// that operational check.
func ParseLeafPEM(certificatePEM, privateKeyPEM []byte) (*LeafMaterial, error) {
	certificate, key, err := ParseKeyPairPEM(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return newLeafMaterial(certificate, key)
}

// ValidateRoot checks an issued root's private key, structural constraints,
// self-signature, and validity at at. A zero at uses the current UTC time.
func ValidateRoot(root *RootMaterial, at time.Time) error {
	if root == nil || root.Certificate == nil || root.PrivateKey == nil {
		return errors.New("root certificate and private key are required")
	}
	at = normalizedTime(at)
	if err := validateRootCertificate(root.Certificate, at); err != nil {
		return err
	}
	return validateRootKeyMaterial(root)
}

func validateRootKeyMaterial(root *RootMaterial) error {
	if err := validateP256PrivateKey(root.PrivateKey); err != nil {
		return fmt.Errorf("root private key: %w", err)
	}
	if !publicKeysEqual(root.Certificate.PublicKey, &root.PrivateKey.PublicKey) {
		return errors.New("root certificate does not match private key")
	}
	expectedKeyID, err := publicKeyID(&root.PrivateKey.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(root.Certificate.SubjectKeyId, expectedKeyID) || !bytes.Equal(root.Certificate.AuthorityKeyId, expectedKeyID) {
		return errors.New("root key identifiers do not match public key")
	}
	return nil
}

// ValidateLeaf validates a directly-issued leaf against one of roots at at.
// It requires an exact profile, a matching private key, canonical SANs, and a
// direct root signature. A zero at uses the current UTC time.
func ValidateLeaf(leaf *LeafMaterial, roots []*x509.Certificate, profile Profile, at time.Time) error {
	if leaf == nil || leaf.Certificate == nil || leaf.PrivateKey == nil {
		return errors.New("leaf certificate and private key are required")
	}
	spec, err := profileSpec(profile)
	if err != nil {
		return err
	}
	certificate := leaf.Certificate
	if err := validateP256Certificate(certificate); err != nil {
		return fmt.Errorf("leaf certificate: %w", err)
	}
	if err := validateP256PrivateKey(leaf.PrivateKey); err != nil {
		return fmt.Errorf("leaf private key: %w", err)
	}
	if !publicKeysEqual(certificate.PublicKey, &leaf.PrivateKey.PublicKey) {
		return errors.New("leaf certificate does not match private key")
	}
	expectedLeafKeyID, err := publicKeyID(certificate.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(certificate.SubjectKeyId, expectedLeafKeyID) {
		return errors.New("leaf subject key identifier does not match public key")
	}
	if certificate.Version != 3 || certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 || certificate.SerialNumber.BitLen() > 128 || !certificate.NotAfter.After(certificate.NotBefore) {
		return errors.New("leaf certificate has an invalid serial number")
	}
	if certificate.SignatureAlgorithm != x509.ECDSAWithSHA256 || certificate.KeyUsage != x509.KeyUsageDigitalSignature || !certificate.BasicConstraintsValid || certificate.IsCA || certificate.MaxPathLen != -1 || certificate.MaxPathLenZero {
		return errors.New("leaf certificate has invalid CA or key-usage constraints")
	}
	if len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != spec.usage || len(certificate.UnknownExtKeyUsage) != 0 {
		return errors.New("leaf certificate has invalid extended key usage")
	}
	if len(certificate.EmailAddresses) != 0 || len(certificate.URIs) != 0 {
		return errors.New("leaf certificate has unsupported subject alternative names")
	}
	sans, err := CanonicalSANs(certificate.DNSNames, certificate.IPAddresses)
	if err != nil {
		return err
	}
	if !equalStrings(certificate.DNSNames, sans.DNSNames) || !equalIPs(certificate.IPAddresses, sans.IPAddresses) {
		return errors.New("leaf certificate subject alternative names are not canonical")
	}
	if err := spec.validateSANs(sans); err != nil {
		return err
	}
	now := normalizedTime(at)
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return errors.New("leaf certificate is not currently valid")
	}

	rootPool := x509.NewCertPool()
	var issuingRoot *x509.Certificate
	for _, root := range roots {
		if root == nil {
			continue
		}
		if err := validateRootCertificate(root, now); err != nil {
			continue
		}
		rootPool.AddCert(root)
		if certificate.CheckSignatureFrom(root) == nil {
			issuingRoot = root
		}
	}
	if issuingRoot == nil {
		return errors.New("leaf certificate is not directly signed by a valid root")
	}
	if len(certificate.AuthorityKeyId) == 0 || !bytes.Equal(certificate.AuthorityKeyId, issuingRoot.SubjectKeyId) {
		return errors.New("leaf authority key identifier does not match issuer")
	}
	if certificate.NotAfter.After(issuingRoot.NotAfter) {
		return errors.New("leaf certificate outlives issuer root")
	}
	if certificate.NotBefore.Before(issuingRoot.NotBefore) {
		return errors.New("leaf certificate becomes valid before issuer root")
	}
	_, err = certificate.Verify(x509.VerifyOptions{
		Roots:       rootPool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{spec.usage},
	})
	if err != nil {
		return fmt.Errorf("verify leaf chain: %w", err)
	}
	return nil
}

// ParseCertificatePEM parses exactly one unencrypted PEM certificate block.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	certificates, err := ParseCertificatesPEM(data)
	if err != nil {
		return nil, err
	}
	if len(certificates) != 1 {
		return nil, fmt.Errorf("expected exactly one certificate, got %d", len(certificates))
	}
	return certificates[0], nil
}

// ParseCertificatesPEM parses one or more unencrypted PEM certificate blocks
// and rejects non-certificate content.
func ParseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	remaining := bytes.TrimSpace(data)
	if len(remaining) == 0 {
		return nil, errors.New("certificate PEM is empty")
	}
	certificates := make([]*x509.Certificate, 0, 1)
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, errors.New("certificate PEM contains invalid or trailing data")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("PEM contains a non-certificate block")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certificates = append(certificates, certificate)
		remaining = bytes.TrimSpace(rest)
	}
	return certificates, nil
}

// ParsePrivateKeyPEM parses exactly one unencrypted ECDSA P-256 private key.
// Both SEC 1 (EC PRIVATE KEY) and PKCS #8 (PRIVATE KEY) encoding are accepted.
func ParsePrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	remaining := bytes.TrimSpace(data)
	if len(remaining) == 0 {
		return nil, errors.New("private key PEM is empty")
	}
	block, rest := pem.Decode(remaining)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("private key PEM must contain exactly one block")
	}
	if len(block.Headers) != 0 {
		return nil, errors.New("encrypted or header-bearing private keys are not supported")
	}
	var key *ecdsa.PrivateKey
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.New("private key is not ECDSA")
			}
		}
	default:
		return nil, fmt.Errorf("unsupported private key PEM type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	if err := validateP256PrivateKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

// ParseKeyPairPEM parses a single certificate and matching ECDSA P-256
// private key.
func ParseKeyPairPEM(certificatePEM, privateKeyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certificate, err := ParseCertificatePEM(certificatePEM)
	if err != nil {
		return nil, nil, err
	}
	if err := validateP256Certificate(certificate); err != nil {
		return nil, nil, fmt.Errorf("certificate: %w", err)
	}
	key, err := ParsePrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	if !publicKeysEqual(certificate.PublicKey, &key.PublicKey) {
		return nil, nil, errors.New("certificate does not match private key")
	}
	return certificate, key, nil
}

// EncodeCertificatePEM returns the canonical PEM encoding of certificate.
func EncodeCertificatePEM(certificate *x509.Certificate) ([]byte, error) {
	if certificate == nil || len(certificate.Raw) == 0 {
		return nil, errors.New("certificate is required")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), nil
}

// EncodeCertificatesPEM returns a PEM bundle in the supplied order. The first
// certificate is conventionally the leaf when encoding a TLS chain.
func EncodeCertificatesPEM(certificates ...*x509.Certificate) ([]byte, error) {
	if len(certificates) == 0 {
		return nil, errors.New("at least one certificate is required")
	}
	var out bytes.Buffer
	for _, certificate := range certificates {
		encoded, err := EncodeCertificatePEM(certificate)
		if err != nil {
			return nil, err
		}
		out.Write(encoded)
	}
	return out.Bytes(), nil
}

// EncodePrivateKeyPEM returns an unencrypted PKCS #8 PEM encoding. The key
// must be ECDSA P-256.
func EncodePrivateKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	if err := validateP256PrivateKey(key); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// CertificateFingerprint returns a stable lower-case hexadecimal SHA-256
// fingerprint of a certificate's DER encoding. It never includes private key
// material.
func CertificateFingerprint(certificate *x509.Certificate) string {
	if certificate == nil || len(certificate.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(sum[:])
}

// Fingerprint returns the root certificate's SHA-256 fingerprint.
func (root *RootMaterial) Fingerprint() string {
	if root == nil {
		return ""
	}
	return CertificateFingerprint(root.Certificate)
}

// Fingerprint returns the leaf certificate's SHA-256 fingerprint.
func (leaf *LeafMaterial) Fingerprint() string {
	if leaf == nil {
		return ""
	}
	return CertificateFingerprint(leaf.Certificate)
}

type profileDetails struct {
	usage             x509.ExtKeyUsage
	requireSAN        bool
	requireDNS        bool
	forbidIPAddresses bool
}

func profileSpec(profile Profile) (profileDetails, error) {
	switch profile {
	case ProfileWebhook:
		return profileDetails{usage: x509.ExtKeyUsageServerAuth, requireSAN: true, requireDNS: true, forbidIPAddresses: true}, nil
	case ProfileServer:
		return profileDetails{usage: x509.ExtKeyUsageServerAuth, requireSAN: true}, nil
	case ProfileClient:
		return profileDetails{usage: x509.ExtKeyUsageClientAuth}, nil
	default:
		return profileDetails{}, fmt.Errorf("%w %q", ErrInvalidProfile, profile)
	}
}

func (profile profileDetails) validateSANs(sans SANs) error {
	if profile.requireDNS && len(sans.DNSNames) == 0 {
		return errors.New("webhook profile requires at least one DNS SAN")
	}
	if profile.requireSAN && len(sans.DNSNames) == 0 && len(sans.IPAddresses) == 0 {
		return errors.New("certificate profile requires at least one DNS or IP SAN")
	}
	if profile.forbidIPAddresses && len(sans.IPAddresses) != 0 {
		return errors.New("webhook profile does not permit IP SANs")
	}
	return nil
}

func newRootMaterial(certificate *x509.Certificate, key *ecdsa.PrivateKey) (*RootMaterial, error) {
	certificatePEM, err := EncodeCertificatePEM(certificate)
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := EncodePrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	return &RootMaterial{Certificate: certificate, PrivateKey: key, CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM}, nil
}

func newLeafMaterial(certificate *x509.Certificate, key *ecdsa.PrivateKey) (*LeafMaterial, error) {
	certificatePEM, err := EncodeCertificatePEM(certificate)
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := EncodePrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	return &LeafMaterial{Certificate: certificate, PrivateKey: key, CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM}, nil
}

func validateRootCertificate(certificate *x509.Certificate, at time.Time) error {
	if certificate == nil {
		return errors.New("root certificate is required")
	}
	if err := validateP256Certificate(certificate); err != nil {
		return fmt.Errorf("root certificate: %w", err)
	}
	if strings.TrimSpace(certificate.Subject.CommonName) == "" || certificate.Subject.String() != certificate.Issuer.String() {
		return errors.New("root certificate must be self-issued with a common name")
	}
	if certificate.Version != 3 || certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 || certificate.SerialNumber.BitLen() > 128 || !certificate.NotAfter.After(certificate.NotBefore) {
		return errors.New("root certificate has an invalid serial number")
	}
	if certificate.SignatureAlgorithm != x509.ECDSAWithSHA256 || !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.MaxPathLen != -1 || certificate.MaxPathLenZero {
		return errors.New("root certificate has invalid CA constraints")
	}
	requiredUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if certificate.KeyUsage != requiredUsage || len(certificate.ExtKeyUsage) != 0 || len(certificate.UnknownExtKeyUsage) != 0 {
		return errors.New("root certificate has invalid key usage")
	}
	if len(certificate.DNSNames) != 0 || len(certificate.IPAddresses) != 0 || len(certificate.EmailAddresses) != 0 || len(certificate.URIs) != 0 {
		return errors.New("root certificate must not contain subject alternative names")
	}
	if len(certificate.SubjectKeyId) == 0 || !bytes.Equal(certificate.SubjectKeyId, certificate.AuthorityKeyId) {
		return errors.New("root certificate has invalid key identifiers")
	}
	expectedKeyID, err := publicKeyID(certificate.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(certificate.SubjectKeyId, expectedKeyID) {
		return errors.New("root subject key identifier does not match public key")
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return fmt.Errorf("root certificate is not self-signed: %w", err)
	}
	if !at.IsZero() {
		now := normalizedTime(at)
		if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return errors.New("root certificate is not currently valid")
		}
	}
	return nil
}

func validateP256Certificate(certificate *x509.Certificate) error {
	if certificate == nil {
		return errors.New("certificate is required")
	}
	key, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("certificate public key is not ECDSA")
	}
	if certificate.PublicKeyAlgorithm != x509.ECDSA || key.Curve != elliptic.P256() {
		return errors.New("certificate public key is not ECDSA P-256")
	}
	return nil
}

func validateP256PrivateKey(key *ecdsa.PrivateKey) error {
	if key == nil || key.D == nil || key.X == nil || key.Y == nil {
		return errors.New("private key is required")
	}
	if key.Curve != elliptic.P256() {
		return errors.New("private key is not ECDSA P-256")
	}
	if key.D.Sign() <= 0 || key.D.Cmp(elliptic.P256().Params().N) >= 0 || !elliptic.P256().IsOnCurve(key.X, key.Y) {
		return errors.New("private key public point is invalid")
	}
	expectedX, expectedY := elliptic.P256().ScalarBaseMult(key.D.Bytes())
	if expectedX.Cmp(key.X) != 0 || expectedY.Cmp(key.Y) != 0 {
		return errors.New("private key scalar does not match public point")
	}
	return nil
}

func canonicalSubject(subject pkix.Name, commonName string) (pkix.Name, error) {
	commonName = strings.TrimSpace(commonName)
	if commonName != "" && subject.CommonName != "" && strings.TrimSpace(subject.CommonName) != commonName {
		return pkix.Name{}, errors.New("subject common name conflicts with common name option")
	}
	if commonName != "" {
		subject.CommonName = commonName
	} else {
		subject.CommonName = strings.TrimSpace(subject.CommonName)
	}
	if subject.CommonName == "" {
		return pkix.Name{}, errors.New("certificate common name is required")
	}
	return subject, nil
}

func canonicalDNSName(name string) (string, error) {
	canonical := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if canonical == "" || len(canonical) > 253 || net.ParseIP(canonical) != nil {
		return "", fmt.Errorf("%w %q", ErrInvalidSAN, name)
	}
	labels := strings.Split(canonical, ".")
	for index, label := range labels {
		if label == "*" && index == 0 && len(labels) > 1 {
			continue
		}
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("%w %q", ErrInvalidSAN, name)
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return "", fmt.Errorf("%w %q", ErrInvalidSAN, name)
			}
		}
	}
	return canonical, nil
}

func canonicalIP(ip net.IP) (netip.Addr, error) {
	address, ok := netip.AddrFromSlice(ip)
	if !ok || address.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%w %q", ErrInvalidSAN, ip.String())
	}
	return address.Unmap(), nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, fmt.Errorf("generate serial number: %w", err)
		}
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}

func publicKeyID(publicKey any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return append([]byte(nil), sum[:]...), nil
}

func publicKeysEqual(first, second any) bool {
	firstKey, ok := first.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	secondKey, ok := second.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	if firstKey.Curve == nil || secondKey.Curve == nil || firstKey.X == nil || firstKey.Y == nil || secondKey.X == nil || secondKey.Y == nil {
		return false
	}
	return firstKey.Curve == secondKey.Curve && firstKey.X.Cmp(secondKey.X) == 0 && firstKey.Y.Cmp(secondKey.Y) == 0
}

func validityOrDefault(validity, fallback time.Duration) (time.Duration, error) {
	if validity == 0 {
		return fallback, nil
	}
	if validity < 0 {
		return 0, errors.New("must be positive")
	}
	return validity, nil
}

func normalizedTime(value time.Time) time.Time {
	if value.IsZero() {
		value = time.Now()
	}
	return value.UTC().Truncate(time.Second)
}

func cloneIPs(addresses []net.IP) []net.IP {
	cloned := make([]net.IP, len(addresses))
	for index, address := range addresses {
		cloned[index] = append(net.IP(nil), address...)
	}
	return cloned
}

func equalIPs(first, second []net.IP) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if !first[index].Equal(second[index]) {
			return false
		}
	}
	return true
}

func equalStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}
