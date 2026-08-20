package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/zeisthq/zeist-pki/pki"
	"github.com/zeisthq/zeist-pki/rotation"
)

// Issuer owns the self-managed private roots held in a StateStore Secret. It
// is intentionally not an arbitrary issuer framework: it implements only the
// the built-in profiles and keeps root keys out of consumer output Secrets.
type Issuer struct {
	Client kubernetes.Interface
	Names  Names
	Now    func() time.Time
}

type rootAuthority struct {
	material    *pki.RootMaterial
	certificate *x509.Certificate
}

func (i Issuer) now() time.Time {
	if i.Now != nil {
		return i.Now().UTC()
	}
	return time.Now().UTC()
}

// GuardBootstrap fails closed when an authoritative state record vanished but
// issuer authority, certificate outputs, or admission trust still carry
// material. Empty fixed-name placeholders are intentionally allowed so a
// least-privilege deployment can pre-create them.
func (i Issuer) GuardBootstrap(ctx context.Context, domain rotation.Domain) error {
	if domain.Profile == rotation.ProfileWebhook {
		if err := i.Names.validateWebhookCanary(); err != nil {
			return err
		}
		for _, name := range i.webhookConfigurationNames() {
			if err := i.guardEmptyWebhookTrust(ctx, name); err != nil {
				return err
			}
		}
	}
	stateSecret, err := i.Client.CoreV1().Secrets(i.Names.Namespace).Get(ctx, StateSecretName(domain.Name), metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("read issuer state Secret %s: %w", StateSecretName(domain.Name), err)
	}
	if err == nil && hasSecretMaterial(stateSecret) {
		return fmt.Errorf("issuer state Secret %s retains authority material; run guarded recover", stateSecret.Name)
	}
	outputs, err := i.outputSecrets(domain)
	if err != nil {
		return err
	}
	for _, output := range outputs {
		secret, err := i.Client.CoreV1().Secrets(output.namespace).Get(ctx, output.name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		if hasSecretMaterial(secret) {
			return fmt.Errorf("issuer state is missing while managed output Secret %s/%s survives; run guarded recover", output.namespace, output.name)
		}
	}
	return nil
}

func (i Issuer) webhookConfigurationNames() []string {
	names := make([]string, 0, len(i.Names.WebhookConfigurationNames)+1)
	seen := make(map[string]struct{}, len(i.Names.WebhookConfigurationNames)+1)
	for _, name := range append(append([]string(nil), i.Names.WebhookConfigurationNames...), i.Names.WebhookCanaryConfiguration) {
		if name == "" {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

// guardEmptyWebhookTrust rejects surviving trust from every explicitly named
// admission configuration. It intentionally checks every caBundle in the
// named resource rather than only the currently selected Service: losing PKI
// state while any trust in an owned configuration survives is ambiguous and
// must require explicit recovery, not a silent new root.
func (i Issuer) guardEmptyWebhookTrust(ctx context.Context, name string) error {
	mutating, err := i.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		for _, webhook := range mutating.Webhooks {
			if len(webhook.ClientConfig.CABundle) != 0 {
				return fmt.Errorf("issuer state is missing while named webhook configuration %s retains a CA bundle; run guarded recover", name)
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("read mutating webhook configuration %s: %w", name, err)
	}
	validating, err := i.Client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read validating webhook configuration %s: %w", name, err)
	}
	for _, webhook := range validating.Webhooks {
		if len(webhook.ClientConfig.CABundle) != 0 {
			return fmt.Errorf("issuer state is missing while named webhook configuration %s retains a CA bundle; run guarded recover", name)
		}
	}
	return nil
}

// CreateRoot issues a new independent ECDSA P-256 root. StateStore persists
// its opaque authority before the reconciler requests any leaf issuance.
func (i Issuer) CreateRoot(_ context.Context, domain rotation.Domain) (rotation.Root, error) {
	material, err := pki.IssueRoot(pki.RootOptions{
		CommonName: "zeist-pki " + domain.Name + " private root",
		Validity:   domain.Policy.RootValidity,
		Now:        i.now(),
	})
	if err != nil {
		return rotation.Root{}, err
	}
	return rootFromMaterial(material), nil
}

// Issue produces the fixed output set for one operation. If a process died
// after publication, existing outputs bearing that exact operation identity
// are parsed and reused instead of minting a different leaf generation.
func (i Issuer) Issue(ctx context.Context, request rotation.IssueRequest) (rotation.Publication, error) {
	if request.Domain.Profile == rotation.ProfileWebhook {
		if err := i.Names.validateWebhookCanary(); err != nil {
			return rotation.Publication{}, err
		}
	}
	if err := validateIssueRootReferences(request); err != nil {
		return rotation.Publication{}, err
	}
	_, trustCertificates, err := requestTrustRoots(request.TrustRoots)
	if err != nil {
		return rotation.Publication{}, err
	}
	trustBundle, err := pki.EncodeCertificatesPEM(trustCertificates...)
	if err != nil {
		return rotation.Publication{}, err
	}
	trustFingerprint := bundleFingerprint(trustCertificates)
	if request.ReuseExistingLeaves {
		return i.reuseExistingLeaves(ctx, request, trustCertificates, trustBundle, trustFingerprint)
	}
	signer, err := authorityMaterial(request.Signer)
	if err != nil {
		return rotation.Publication{}, fmt.Errorf("load signing root: %w", err)
	}

	material := PublicationMaterial{TrustBundle: trustBundle}
	publication := rotation.Publication{Materials: make(map[string]rotation.MaterialFingerprint)}
	var leafExpiry time.Time
	switch request.Domain.Profile {
	case rotation.ProfileWebhook:
		data, fingerprint, notAfter, err := i.webhookOutput(ctx, request, signer, trustCertificates, trustFingerprint)
		if err != nil {
			return rotation.Publication{}, err
		}
		material.WebhookTLS = data
		publication.Materials["webhook"] = rotation.MaterialFingerprint{LeafFingerprint: fingerprint, TrustFingerprint: trustFingerprint}
		leafExpiry = notAfter
		canarySigner, err := candidateWebhookSigner(request, signer)
		if err != nil {
			return rotation.Publication{}, err
		}
		canaryTrustBundle, canaryTrustFingerprint, canaryRoots, err := canaryTrustMaterial(canarySigner)
		if err != nil {
			return rotation.Publication{}, err
		}
		canary, canaryFingerprint, canaryNotAfter, err := i.webhookCanaryOutput(ctx, request, canarySigner, canaryRoots, canaryTrustFingerprint)
		if err != nil {
			return rotation.Publication{}, err
		}
		material.WebhookCanaryTLS = canary
		material.CanaryTrustBundle = canaryTrustBundle
		publication.Materials["canary"] = rotation.MaterialFingerprint{LeafFingerprint: canaryFingerprint, TrustFingerprint: canaryTrustFingerprint}
		if canaryNotAfter.Before(leafExpiry) {
			leafExpiry = canaryNotAfter
		}
	case rotation.ProfileMTLS:
		server, serverFingerprint, serverExpiry, err := i.serverOutput(ctx, request, signer, trustCertificates, trustBundle, trustFingerprint)
		if err != nil {
			return rotation.Publication{}, err
		}
		client, clientFingerprint, clientExpiry, err := i.clientOutput(ctx, request, signer, trustCertificates, trustBundle, trustFingerprint)
		if err != nil {
			return rotation.Publication{}, err
		}
		material.ServerTLS, material.ClientTLS = server, client
		publication.Materials["server"] = rotation.MaterialFingerprint{LeafFingerprint: serverFingerprint, TrustFingerprint: trustFingerprint}
		publication.Materials["client"] = rotation.MaterialFingerprint{LeafFingerprint: clientFingerprint, TrustFingerprint: trustFingerprint}
		leafExpiry = serverExpiry
		if clientExpiry.Before(leafExpiry) {
			leafExpiry = clientExpiry
		}
	case rotation.ProfileServiceMTLS:
		configured, err := i.Names.serviceMTLS(request.Domain.Name)
		if err != nil {
			return rotation.Publication{}, err
		}
		server, serverFingerprint, serverExpiry, err := i.serviceServerOutput(ctx, request, configured, signer, trustCertificates, trustBundle, trustFingerprint)
		if err != nil {
			return rotation.Publication{}, err
		}
		client, clientFingerprint, clientExpiry, err := i.serviceClientOutput(ctx, request, configured, signer, trustCertificates, trustBundle, trustFingerprint)
		if err != nil {
			return rotation.Publication{}, err
		}
		material.ServerTLS, material.ClientTLS = server, client
		publication.Materials["server"] = rotation.MaterialFingerprint{LeafFingerprint: serverFingerprint, TrustFingerprint: trustFingerprint}
		publication.Materials["client"] = rotation.MaterialFingerprint{LeafFingerprint: clientFingerprint, TrustFingerprint: trustFingerprint}
		leafExpiry = serverExpiry
		if clientExpiry.Before(leafExpiry) {
			leafExpiry = clientExpiry
		}
	default:
		return rotation.Publication{}, fmt.Errorf("unsupported domain profile %q", request.Domain.Profile)
	}
	publication.LeafNotAfter = leafExpiry
	publication.Opaque = &material
	return publication, nil
}

func validateIssueRootReferences(request rotation.IssueRequest) error {
	if !containsRootFingerprint(request.TrustRoots, request.Signer.Fingerprint) {
		return fmt.Errorf("issuance signing root %q is absent from the trust bundle", request.Signer.Fingerprint)
	}
	if request.DualTrust {
		if request.Candidate == nil {
			return fmt.Errorf("dual-trust issuance has no candidate root")
		}
		if !containsRootFingerprint(request.TrustRoots, request.Candidate.Fingerprint) {
			return fmt.Errorf("issuance candidate root %q is absent from the trust bundle", request.Candidate.Fingerprint)
		}
	}
	return nil
}

func containsRootFingerprint(roots []rotation.Root, fingerprint string) bool {
	for _, root := range roots {
		if root.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

// reuseExistingLeaves is the only path that may keep an old leaf while
// changing its trust bundle. It is reached exclusively after explicit
// fingerprint-confirmed recovery of a root whose private key is unavailable.
func (i Issuer) reuseExistingLeaves(ctx context.Context, request rotation.IssueRequest, roots []*x509.Certificate, trustBundle []byte, trustFingerprint string) (rotation.Publication, error) {
	publication := rotation.Publication{Materials: make(map[string]rotation.MaterialFingerprint)}
	switch request.Domain.Profile {
	case rotation.ProfileWebhook:
		data, fingerprint, notAfter, err := i.reuseExistingOutput(ctx, i.Names.Namespace, i.Names.WebhookSecret, pki.ProfileWebhook, roots, nil)
		if err != nil {
			return rotation.Publication{}, err
		}
		canarySigner, err := candidateWebhookSigner(request, nil)
		if err != nil {
			return rotation.Publication{}, err
		}
		canaryTrustBundle, canaryTrustFingerprint, canaryRoots, err := canaryTrustMaterial(canarySigner)
		if err != nil {
			return rotation.Publication{}, err
		}
		canary, canaryFingerprint, canaryNotAfter, err := i.webhookCanaryOutput(ctx, request, canarySigner, canaryRoots, canaryTrustFingerprint)
		if err != nil {
			return rotation.Publication{}, err
		}
		publication.Materials["webhook"] = rotation.MaterialFingerprint{LeafFingerprint: fingerprint, TrustFingerprint: trustFingerprint}
		publication.Materials["canary"] = rotation.MaterialFingerprint{LeafFingerprint: canaryFingerprint, TrustFingerprint: canaryTrustFingerprint}
		publication.LeafNotAfter = notAfter
		if canaryNotAfter.Before(publication.LeafNotAfter) {
			publication.LeafNotAfter = canaryNotAfter
		}
		publication.Opaque = &PublicationMaterial{WebhookTLS: data, WebhookCanaryTLS: canary, TrustBundle: trustBundle, CanaryTrustBundle: canaryTrustBundle}
		return publication, nil
	case rotation.ProfileMTLS:
		server, serverFingerprint, serverExpiry, err := i.reuseExistingOutput(ctx, i.Names.Namespace, i.Names.ServerSecret, pki.ProfileServer, roots, trustBundle)
		if err != nil {
			return rotation.Publication{}, err
		}
		client, clientFingerprint, clientExpiry, err := i.reuseExistingOutput(ctx, i.Names.Namespace, i.Names.ClientSecret, pki.ProfileClient, roots, trustBundle)
		if err != nil {
			return rotation.Publication{}, err
		}
		leafExpiry := serverExpiry
		if clientExpiry.Before(leafExpiry) {
			leafExpiry = clientExpiry
		}
		publication.Materials["server"] = rotation.MaterialFingerprint{LeafFingerprint: serverFingerprint, TrustFingerprint: trustFingerprint}
		publication.Materials["client"] = rotation.MaterialFingerprint{LeafFingerprint: clientFingerprint, TrustFingerprint: trustFingerprint}
		publication.LeafNotAfter = leafExpiry
		publication.Opaque = &PublicationMaterial{ServerTLS: server, ClientTLS: client, TrustBundle: trustBundle}
		return publication, nil
	case rotation.ProfileServiceMTLS:
		configured, err := i.Names.serviceMTLS(request.Domain.Name)
		if err != nil {
			return rotation.Publication{}, err
		}
		server, serverFingerprint, serverExpiry, err := i.reuseExistingOutput(ctx, configured.ServerNamespace, configured.ServerSecret, pki.ProfileServer, roots, trustBundle)
		if err != nil {
			return rotation.Publication{}, err
		}
		if err := validateServiceCertificateIdentity(server["tls.crt"], configured); err != nil {
			return rotation.Publication{}, fmt.Errorf("validate surviving service server identity: %w", err)
		}
		client, clientFingerprint, clientExpiry, err := i.reuseExistingOutput(ctx, configured.ClientNamespace, configured.ClientSecret, pki.ProfileClient, roots, trustBundle)
		if err != nil {
			return rotation.Publication{}, err
		}
		leafExpiry := serverExpiry
		if clientExpiry.Before(leafExpiry) {
			leafExpiry = clientExpiry
		}
		publication.Materials["server"] = rotation.MaterialFingerprint{LeafFingerprint: serverFingerprint, TrustFingerprint: trustFingerprint}
		publication.Materials["client"] = rotation.MaterialFingerprint{LeafFingerprint: clientFingerprint, TrustFingerprint: trustFingerprint}
		publication.LeafNotAfter = leafExpiry
		publication.Opaque = &PublicationMaterial{ServerTLS: server, ClientTLS: client, TrustBundle: trustBundle}
		return publication, nil
	default:
		return rotation.Publication{}, fmt.Errorf("unsupported domain profile %q", request.Domain.Profile)
	}
}

// RetireRoot is intentionally a no-op for the Kubernetes adapter. The
// reconciler has already persisted a state Secret containing only the new
// active root before it calls this hook, which atomically removes the old key
// from the only issuer-authority location.
func (Issuer) RetireRoot(context.Context, rotation.Domain, rotation.Root) error { return nil }

func (i Issuer) webhookOutput(ctx context.Context, request rotation.IssueRequest, signer *pki.RootMaterial, roots []*x509.Certificate, trustFingerprint string) (map[string][]byte, string, time.Time, error) {
	return i.webhookOutputFor(ctx, i.Names.WebhookSecret, i.Names.WebhookService, request, signer, roots, trustFingerprint)
}

func (i Issuer) webhookCanaryOutput(ctx context.Context, request rotation.IssueRequest, signer *pki.RootMaterial, roots []*x509.Certificate, trustFingerprint string) (map[string][]byte, string, time.Time, error) {
	if request.ReuseExistingLeaves {
		secret, err := i.Client.CoreV1().Secrets(i.Names.Namespace).Get(ctx, i.Names.WebhookCanarySecret, metav1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, "", time.Time{}, err
		}
		if err == nil && hasSecretMaterial(secret) {
			// Guarded recovery may replace only its known legacy canary output.
			// A distinct managed domain retains its fail-closed ownership fence.
			if domain := secret.Annotations[annotationDomain]; domain != "" && domain != request.Domain.Name {
				return nil, "", time.Time{}, fmt.Errorf("output Secret %s belongs to another domain; refusing replacement", i.Names.WebhookCanarySecret)
			}
			if secret.Annotations[annotationDomain] == request.Domain.Name && secret.Annotations[annotationGeneration] == fmt.Sprintf("%d", request.Generation) && secret.Annotations[annotationOperation] == request.OperationID {
				return i.webhookOutputFor(ctx, i.Names.WebhookCanarySecret, i.Names.WebhookCanaryService, request, signer, roots, trustFingerprint)
			}
			return issueWebhookOutput(signer, i.Names.Namespace, i.Names.WebhookCanaryService, request.Domain.Policy.LeafValidity, i.now(), trustFingerprint)
		}
	}
	return i.webhookOutputFor(ctx, i.Names.WebhookCanarySecret, i.Names.WebhookCanaryService, request, signer, roots, trustFingerprint)
}

func (i Issuer) webhookOutputFor(ctx context.Context, name, service string, request rotation.IssueRequest, signer *pki.RootMaterial, roots []*x509.Certificate, trustFingerprint string) (map[string][]byte, string, time.Time, error) {
	if data, fingerprint, notAfter, found, err := i.existingOutput(ctx, i.Names.Namespace, name, request, pki.ProfileWebhook, roots, nil, trustFingerprint); err != nil || found {
		if err == nil && found {
			leaf, parseErr := pki.ParseLeafPEM(data["tls.crt"], data["tls.key"])
			if parseErr != nil {
				return nil, "", time.Time{}, fmt.Errorf("parse existing webhook output Secret %s: %w", name, parseErr)
			}
			if identityErr := validateWebhookServiceCertificate(leaf.Certificate, i.Names.Namespace, service); identityErr != nil {
				return nil, "", time.Time{}, fmt.Errorf("validate existing webhook output Secret %s identity: %w", name, identityErr)
			}
		}
		return data, fingerprint, notAfter, err
	}
	return issueWebhookOutput(signer, i.Names.Namespace, service, request.Domain.Policy.LeafValidity, i.now(), trustFingerprint)
}

func issueWebhookOutput(signer *pki.RootMaterial, namespace, service string, validity time.Duration, now time.Time, trustFingerprint string) (map[string][]byte, string, time.Time, error) {
	dns := []string{service + "." + namespace + ".svc", service + "." + namespace + ".svc.cluster.local"}
	return issueOutput(signer, pki.LeafOptions{CommonName: dns[0], Profile: pki.ProfileWebhook, DNSNames: dns, Validity: validity, Now: now}, nil, trustFingerprint)
}

func validateWebhookServiceCertificate(certificate *x509.Certificate, namespace, service string) error {
	if certificate == nil {
		return fmt.Errorf("certificate is required")
	}
	host := service + "." + namespace + ".svc"
	if err := certificate.VerifyHostname(host); err != nil {
		return fmt.Errorf("certificate does not identify %s: %w", host, err)
	}
	return nil
}

// candidateWebhookSigner deliberately uses the named candidate rather than
// TrustRoots ordering. During PublishingDualTrust the production leaf is still
// active-signed but this canary must be candidate-signed; during candidate leaf
// activation the two identities are the same. The portable reconciler supplies
// Candidate explicitly because TrustRoots is canonicalized by fingerprint.
func candidateWebhookSigner(request rotation.IssueRequest, fallback *pki.RootMaterial) (*pki.RootMaterial, error) {
	if !request.DualTrust {
		if fallback == nil {
			return nil, fmt.Errorf("webhook issuance has no signing root")
		}
		return fallback, nil
	}
	if request.Candidate == nil {
		return nil, fmt.Errorf("dual-trust webhook issuance has no candidate root")
	}
	material, err := authorityMaterial(*request.Candidate)
	if err != nil {
		return nil, fmt.Errorf("load candidate webhook signing root: %w", err)
	}
	return material, nil
}

func canaryTrustMaterial(signer *pki.RootMaterial) ([]byte, string, []*x509.Certificate, error) {
	if signer == nil || signer.Certificate == nil {
		return nil, "", nil, fmt.Errorf("canary signing root is required")
	}
	roots := []*x509.Certificate{signer.Certificate}
	bundle, err := pki.EncodeCertificatesPEM(roots...)
	if err != nil {
		return nil, "", nil, err
	}
	return bundle, bundleFingerprint(roots), roots, nil
}

func (i Issuer) serverOutput(ctx context.Context, request rotation.IssueRequest, signer *pki.RootMaterial, roots []*x509.Certificate, trustBundle []byte, trustFingerprint string) (map[string][]byte, string, time.Time, error) {
	if data, fingerprint, notAfter, found, err := i.existingOutput(ctx, i.Names.Namespace, i.Names.ServerSecret, request, pki.ProfileServer, roots, trustBundle, trustFingerprint); err != nil || found {
		return data, fingerprint, notAfter, err
	}
	service := i.Names.RunnerService
	if service == "" {
		service = "zeistd"
	}
	dns := []string{service + "." + i.Names.Namespace + ".svc", service + "." + i.Names.Namespace + ".svc.cluster.local"}
	ips, err := ipsFromTargets(request.Targets)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	return issueOutput(signer, pki.LeafOptions{CommonName: service, Profile: pki.ProfileServer, DNSNames: dns, IPAddresses: ips, Validity: request.Domain.Policy.LeafValidity, Now: i.now()}, trustBundle, trustFingerprint)
}

func (i Issuer) clientOutput(ctx context.Context, request rotation.IssueRequest, signer *pki.RootMaterial, roots []*x509.Certificate, trustBundle []byte, trustFingerprint string) (map[string][]byte, string, time.Time, error) {
	if data, fingerprint, notAfter, found, err := i.existingOutput(ctx, i.Names.Namespace, i.Names.ClientSecret, request, pki.ProfileClient, roots, trustBundle, trustFingerprint); err != nil || found {
		return data, fingerprint, notAfter, err
	}
	return issueOutput(signer, pki.LeafOptions{CommonName: "zeist-controller", Profile: pki.ProfileClient, Validity: request.Domain.Policy.LeafValidity, Now: i.now()}, trustBundle, trustFingerprint)
}

func (i Issuer) serviceServerOutput(ctx context.Context, request rotation.IssueRequest, configured ServiceMTLSNames, signer *pki.RootMaterial, roots []*x509.Certificate, trustBundle []byte, trustFingerprint string) (map[string][]byte, string, time.Time, error) {
	if data, fingerprint, notAfter, found, err := i.existingOutput(ctx, configured.ServerNamespace, configured.ServerSecret, request, pki.ProfileServer, roots, trustBundle, trustFingerprint); err != nil || found {
		if err == nil && found {
			if identityErr := validateServiceCertificateIdentity(data["tls.crt"], configured); identityErr != nil {
				return nil, "", time.Time{}, fmt.Errorf("validate existing service server identity: %w", identityErr)
			}
		}
		return data, fingerprint, notAfter, err
	}
	shortName, longName := serviceDNSNames(configured)
	return issueOutput(signer, pki.LeafOptions{
		CommonName: shortName, Profile: pki.ProfileServer, DNSNames: []string{shortName, longName},
		Validity: request.Domain.Policy.LeafValidity, Now: i.now(),
	}, trustBundle, trustFingerprint)
}

func (i Issuer) serviceClientOutput(ctx context.Context, request rotation.IssueRequest, configured ServiceMTLSNames, signer *pki.RootMaterial, roots []*x509.Certificate, trustBundle []byte, trustFingerprint string) (map[string][]byte, string, time.Time, error) {
	if data, fingerprint, notAfter, found, err := i.existingOutput(ctx, configured.ClientNamespace, configured.ClientSecret, request, pki.ProfileClient, roots, trustBundle, trustFingerprint); err != nil || found {
		return data, fingerprint, notAfter, err
	}
	return issueOutput(signer, pki.LeafOptions{
		CommonName: request.Domain.Name + " client", Profile: pki.ProfileClient,
		Validity: request.Domain.Policy.LeafValidity, Now: i.now(),
	}, trustBundle, trustFingerprint)
}

func serviceDNSNames(configured ServiceMTLSNames) (string, string) {
	shortName := configured.ServerService + "." + configured.ServerNamespace + ".svc"
	clusterDomain := strings.Trim(configured.ClusterDomain, ".")
	if clusterDomain == "" {
		clusterDomain = "cluster.local"
	}
	return shortName, shortName + "." + clusterDomain
}

func validateServiceCertificateIdentity(certificatePEM []byte, configured ServiceMTLSNames) error {
	certificate, err := pki.ParseCertificatePEM(certificatePEM)
	if err != nil {
		return err
	}
	shortName, _ := serviceDNSNames(configured)
	if err := certificate.VerifyHostname(shortName); err != nil {
		return fmt.Errorf("certificate does not identify %s: %w", shortName, err)
	}
	return nil
}

func issueOutput(signer *pki.RootMaterial, options pki.LeafOptions, trustBundle []byte, trustFingerprint string) (map[string][]byte, string, time.Time, error) {
	leaf, err := pki.IssueLeaf(signer, options)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	data := map[string][]byte{"tls.crt": append([]byte(nil), leaf.CertificatePEM...), "tls.key": append([]byte(nil), leaf.PrivateKeyPEM...)}
	if trustBundle != nil {
		data["ca.crt"] = append([]byte(nil), trustBundle...)
	}
	return data, certificateFingerprint(leaf.Certificate), leaf.Certificate.NotAfter, nil
}

func (i Issuer) existingOutput(ctx context.Context, namespace, name string, request rotation.IssueRequest, profile pki.Profile, roots []*x509.Certificate, trustBundle []byte, trustFingerprint string) (map[string][]byte, string, time.Time, bool, error) {
	secret, err := i.Client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, "", time.Time{}, false, nil
	}
	if err != nil {
		return nil, "", time.Time{}, false, err
	}
	if !hasSecretMaterial(secret) {
		return nil, "", time.Time{}, false, nil
	}
	if secret.Annotations[annotationDomain] != request.Domain.Name {
		return nil, "", time.Time{}, false, fmt.Errorf("output Secret %s belongs to another domain; refusing replacement", name)
	}
	if secret.Annotations[annotationGeneration] != fmt.Sprintf("%d", request.Generation) || secret.Annotations[annotationOperation] != request.OperationID {
		// The operation intent is durable in State before issuance. A different
		// operation from this same domain is a completed (or interrupted) older
		// generation and is safe to supersede with the currently fenced one.
		// Unmanaged material remains fail-closed below.
		return nil, "", time.Time{}, false, nil
	}
	if trustBundle != nil && !bytes.Equal(secret.Data["ca.crt"], trustBundle) {
		return nil, "", time.Time{}, false, fmt.Errorf("output Secret %s has a trust bundle inconsistent with its operation", name)
	}
	leaf, err := pki.ParseLeafPEM(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil {
		return nil, "", time.Time{}, false, fmt.Errorf("parse existing output Secret %s: %w", name, err)
	}
	if err := pki.ValidateLeaf(leaf, roots, profile, i.now()); err != nil {
		return nil, "", time.Time{}, false, fmt.Errorf("validate existing output Secret %s: %w", name, err)
	}
	fingerprint := certificateFingerprint(leaf.Certificate)
	if secret.Annotations[annotationLeafFingerprint] != fingerprint || secret.Annotations[annotationTrustFingerprint] != trustFingerprint {
		return nil, "", time.Time{}, false, fmt.Errorf("output Secret %s annotation fingerprints do not match its material", name)
	}
	return cloneData(secret.Data), fingerprint, leaf.Certificate.NotAfter, true, nil
}

func (i Issuer) reuseExistingOutput(ctx context.Context, namespace, name string, profile pki.Profile, roots []*x509.Certificate, trustBundle []byte) (map[string][]byte, string, time.Time, error) {
	secret, err := i.Client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("read surviving output Secret %s: %w", name, err)
	}
	leaf, err := pki.ParseLeafPEM(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("parse surviving output Secret %s: %w", name, err)
	}
	if err := pki.ValidateLeaf(leaf, roots, profile, i.now()); err != nil {
		return nil, "", time.Time{}, fmt.Errorf("validate surviving output Secret %s: %w", name, err)
	}
	data := cloneData(secret.Data)
	if trustBundle != nil {
		data["ca.crt"] = append([]byte(nil), trustBundle...)
	}
	return data, certificateFingerprint(leaf.Certificate), leaf.Certificate.NotAfter, nil
}

type namespacedSecret struct {
	namespace string
	name      string
}

func (i Issuer) outputSecrets(domain rotation.Domain) ([]namespacedSecret, error) {
	switch domain.Profile {
	case rotation.ProfileWebhook:
		return []namespacedSecret{{i.Names.Namespace, i.Names.WebhookSecret}, {i.Names.Namespace, i.Names.WebhookCanarySecret}}, nil
	case rotation.ProfileMTLS:
		return []namespacedSecret{{i.Names.Namespace, i.Names.ServerSecret}, {i.Names.Namespace, i.Names.ClientSecret}}, nil
	case rotation.ProfileServiceMTLS:
		configured, err := i.Names.serviceMTLS(domain.Name)
		if err != nil {
			return nil, err
		}
		return []namespacedSecret{{configured.ServerNamespace, configured.ServerSecret}, {configured.ClientNamespace, configured.ClientSecret}}, nil
	default:
		return nil, fmt.Errorf("unsupported domain profile %q", domain.Profile)
	}
}

func rootFromMaterial(material *pki.RootMaterial) rotation.Root {
	return rotation.Root{Fingerprint: certificateFingerprint(material.Certificate), NotAfter: material.Certificate.NotAfter, Opaque: &rootAuthority{material: material, certificate: material.Certificate}}
}

func authorityCertificate(root rotation.Root) (*x509.Certificate, error) {
	authority, ok := root.Opaque.(*rootAuthority)
	if !ok || authority == nil || authority.certificate == nil {
		return nil, fmt.Errorf("root %q has no public authority certificate", root.Fingerprint)
	}
	if certificateFingerprint(authority.certificate) != root.Fingerprint || !authority.certificate.NotAfter.Equal(root.NotAfter) {
		return nil, fmt.Errorf("root public authority does not match persisted root reference")
	}
	return authority.certificate, nil
}

func authorityMaterial(root rotation.Root) (*pki.RootMaterial, error) {
	authority, ok := root.Opaque.(*rootAuthority)
	if !ok || authority == nil || authority.material == nil {
		return nil, fmt.Errorf("root %q has no restricted private authority", root.Fingerprint)
	}
	if certificateFingerprint(authority.material.Certificate) != root.Fingerprint || !authority.material.Certificate.NotAfter.Equal(root.NotAfter) {
		return nil, fmt.Errorf("root authority does not match persisted root reference")
	}
	return authority.material, nil
}

func requestTrustRoots(roots []rotation.Root) ([]*pki.RootMaterial, []*x509.Certificate, error) {
	if len(roots) == 0 {
		return nil, nil, fmt.Errorf("issuance request has no trust roots")
	}
	materials := make([]*pki.RootMaterial, 0, len(roots))
	certificates := make([]*x509.Certificate, 0, len(roots))
	seen := map[string]struct{}{}
	for _, root := range roots {
		if _, duplicate := seen[root.Fingerprint]; duplicate {
			return nil, nil, fmt.Errorf("issuance request repeats root %q", root.Fingerprint)
		}
		seen[root.Fingerprint] = struct{}{}
		certificate, err := authorityCertificate(root)
		if err != nil {
			return nil, nil, err
		}
		if authority, ok := root.Opaque.(*rootAuthority); ok && authority.material != nil {
			materials = append(materials, authority.material)
		}
		certificates = append(certificates, certificate)
	}
	return materials, certificates, nil
}

func ipsFromTargets(targets []rotation.Target) ([]net.IP, error) {
	seen := map[string]net.IP{}
	for _, target := range targets {
		if target.Evidence["role"] != "server" {
			continue
		}
		address := net.ParseIP(target.Evidence["internalIP"])
		if address == nil {
			return nil, fmt.Errorf("server target %q has no valid InternalIP", target.ID)
		}
		seen[address.String()] = address
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("issuance request has no server target InternalIP")
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	ips := make([]net.IP, 0, len(values))
	for _, value := range values {
		ips = append(ips, seen[value])
	}
	return ips, nil
}

func certificateFingerprint(certificate *x509.Certificate) string {
	return "sha256:" + pki.CertificateFingerprint(certificate)
}

func bundleFingerprint(certificates []*x509.Certificate) string {
	raw := make([][]byte, 0, len(certificates))
	for _, certificate := range certificates {
		raw = append(raw, certificate.Raw)
	}
	sort.Slice(raw, func(first, second int) bool { return bytes.Compare(raw[first], raw[second]) < 0 })
	digest := sha256.New()
	for _, certificate := range raw {
		_, _ = digest.Write(certificate)
		_, _ = digest.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func hydrateStateAuthorities(secret *corev1.Secret, state *rotation.State) error {
	activeCertificate, active, err := authorityFromSecret(secret, activeCAKey, activeCAKeyKey)
	if err != nil {
		return fmt.Errorf("load active issuer root: %w", err)
	}
	if certificateFingerprint(activeCertificate) != state.Active.Fingerprint || !activeCertificate.NotAfter.Equal(state.Active.NotAfter) {
		return fmt.Errorf("active issuer root does not match state reference")
	}
	if state.ActiveKeyUnavailable != (active == nil) {
		return fmt.Errorf("active issuer key availability does not match state")
	}
	state.Active.Opaque = &rootAuthority{material: active, certificate: activeCertificate}
	if state.Candidate == nil {
		return nil
	}
	candidateCertificate, candidate, err := authorityFromSecret(secret, candidateCAKey, candidateCAKeyKey)
	if err != nil {
		return fmt.Errorf("load candidate issuer root: %w", err)
	}
	if candidate == nil || certificateFingerprint(candidateCertificate) != state.Candidate.Fingerprint || !candidateCertificate.NotAfter.Equal(state.Candidate.NotAfter) {
		return fmt.Errorf("candidate issuer root does not match state reference")
	}
	state.Candidate.Opaque = &rootAuthority{material: candidate, certificate: candidateCertificate}
	return nil
}

func storeStateAuthorities(secret *corev1.Secret, state rotation.State) error {
	activeCertificate, err := authorityCertificate(state.Active)
	if err != nil {
		return fmt.Errorf("active issuer root: %w", err)
	}
	activePEM, err := pki.EncodeCertificatePEM(activeCertificate)
	if err != nil {
		return err
	}
	secret.Data[activeCAKey] = activePEM
	if state.ActiveKeyUnavailable {
		delete(secret.Data, activeCAKeyKey)
	} else {
		active, err := authorityMaterial(state.Active)
		if err != nil {
			return fmt.Errorf("active issuer root: %w", err)
		}
		secret.Data[activeCAKeyKey] = append([]byte(nil), active.PrivateKeyPEM...)
	}
	if state.Candidate == nil {
		delete(secret.Data, candidateCAKey)
		delete(secret.Data, candidateCAKeyKey)
		return nil
	}
	candidate, err := authorityMaterial(*state.Candidate)
	if err != nil {
		return fmt.Errorf("candidate issuer root: %w", err)
	}
	secret.Data[candidateCAKey] = append([]byte(nil), candidate.CertificatePEM...)
	secret.Data[candidateCAKeyKey] = append([]byte(nil), candidate.PrivateKeyPEM...)
	return nil
}

func authorityFromSecret(secret *corev1.Secret, certificateKey, privateKeyKey string) (*x509.Certificate, *pki.RootMaterial, error) {
	certificate, err := DecodeCAData(secret, certificateKey)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := pki.ParseCertificatePEM(certificate)
	if err != nil {
		return nil, nil, err
	}
	key := secret.Data[privateKeyKey]
	if len(key) == 0 {
		if err := validatePublicRoot(parsed); err != nil {
			return nil, nil, err
		}
		return parsed, nil, nil
	}
	material, err := pki.ParseRootPEM(certificate, key)
	if err != nil {
		return nil, nil, err
	}
	return material.Certificate, material, nil
}

func validatePublicRoot(certificate *x509.Certificate) error {
	if certificate == nil || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.CheckSignatureFrom(certificate) != nil {
		return fmt.Errorf("certificate is not a valid self-signed root")
	}
	if certificate.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != (x509.KeyUsageCertSign | x509.KeyUsageCRLSign) {
		return fmt.Errorf("root certificate does not permit certificate signing")
	}
	return nil
}
