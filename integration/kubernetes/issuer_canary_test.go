package kubernetes

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/zeisthq/zeist-pki/pki"
	"github.com/zeisthq/zeist-pki/rotation"
)

func TestIssuerSignsDualTrustCanaryWithCandidateRoot(t *testing.T) {
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	active, err := pki.IssueRoot(pki.RootOptions{CommonName: "active", Validity: 365 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := pki.IssueRoot(pki.RootOptions{CommonName: "candidate", Validity: 365 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	activeRoot := rootFromMaterial(active)
	candidateRoot := rootFromMaterial(candidate)
	domain := rotation.Domain{Name: "webhook", Profile: rotation.ProfileWebhook, ConfigurationHash: "sha256:config", Policy: rotation.DefaultPolicy()}
	issuer := Issuer{
		Client: fake.NewSimpleClientset(),
		Names: Names{
			Namespace: "system", WebhookSecret: "webhook", WebhookService: "manager",
			WebhookCanarySecret: "webhook-canary", WebhookCanaryService: "manager-canary", WebhookCanaryConfiguration: "canary-config",
		},
		Now: func() time.Time { return now },
	}
	request := rotation.IssueRequest{
		Domain: domain, Signer: activeRoot, Candidate: &candidateRoot,
		TrustRoots: []rotation.Root{candidateRoot, activeRoot}, DualTrust: true,
		Generation: 2, OperationID: "dual-trust",
	}
	publication, err := issuer.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	material := publication.Opaque.(*PublicationMaterial)
	primary := parseTestLeaf(t, material.WebhookTLS)
	canary := parseTestLeaf(t, material.WebhookCanaryTLS)
	if err := primary.Certificate.CheckSignatureFrom(active.Certificate); err != nil {
		t.Fatalf("dual-trust production leaf was not active-signed: %v", err)
	}
	if err := canary.Certificate.CheckSignatureFrom(candidate.Certificate); err != nil {
		t.Fatalf("dual-trust canary leaf was not candidate-signed: %v", err)
	}
	if string(material.WebhookTLS["tls.crt"]) == string(material.WebhookCanaryTLS["tls.crt"]) {
		t.Fatal("production and canary must have separate leaves")
	}
	if publication.Materials["canary"].LeafFingerprint != certificateFingerprint(canary.Certificate) {
		t.Fatalf("canary fingerprint = %q", publication.Materials["canary"].LeafFingerprint)
	}
	if publication.Materials["canary"].TrustFingerprint != bundleFingerprint([]*x509.Certificate{candidate.Certificate}) {
		t.Fatalf("canary trust fingerprint = %q", publication.Materials["canary"].TrustFingerprint)
	}
	if bundleFingerprintFromPEM(t, material.CanaryTrustBundle) != publication.Materials["canary"].TrustFingerprint {
		t.Fatal("candidate-only canary trust bundle does not match canary material")
	}

	request.Signer = candidateRoot
	request.Generation = 3
	request.OperationID = "activate-candidate"
	publication, err = issuer.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	material = publication.Opaque.(*PublicationMaterial)
	if err := parseTestLeaf(t, material.WebhookTLS).Certificate.CheckSignatureFrom(candidate.Certificate); err != nil {
		t.Fatalf("candidate activation production leaf was not candidate-signed: %v", err)
	}
	if err := parseTestLeaf(t, material.WebhookCanaryTLS).Certificate.CheckSignatureFrom(candidate.Certificate); err != nil {
		t.Fatalf("candidate activation canary leaf was not candidate-signed: %v", err)
	}
}

func TestIssuerBootstrapGuardIncludesCanaryOutput(t *testing.T) {
	issuer := Issuer{
		Client: fake.NewSimpleClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "webhook-canary", Namespace: "system"}, Data: map[string][]byte{"tls.crt": []byte("surviving")}}),
		Names: Names{
			Namespace: "system", WebhookSecret: "webhook", WebhookService: "manager",
			WebhookCanarySecret: "webhook-canary", WebhookCanaryService: "manager-canary", WebhookCanaryConfiguration: "canary-config",
		},
	}
	domain := rotation.Domain{Name: "webhook", Profile: rotation.ProfileWebhook, ConfigurationHash: "sha256:config", Policy: rotation.DefaultPolicy()}
	if err := issuer.GuardBootstrap(context.Background(), domain); err == nil {
		t.Fatal("bootstrap guard accepted surviving canary output")
	}
}

func TestIssuerBootstrapGuardRejectsSurvivingAuthorityAndNamedWebhookTrust(t *testing.T) {
	domain := rotation.Domain{Name: "webhook", Profile: rotation.ProfileWebhook, ConfigurationHash: "sha256:config", Policy: rotation.DefaultPolicy()}
	names := Names{
		Namespace: "system", WebhookSecret: "webhook", WebhookService: "manager",
		WebhookCanarySecret: "webhook-canary", WebhookCanaryService: "manager-canary", WebhookCanaryConfiguration: "canary-webhooks",
		WebhookConfigurationNames: []string{"webhooks"},
	}
	path := "/validate"
	configuration := func(name, service string, bundle []byte) *admissionv1.ValidatingWebhookConfiguration {
		return &admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Webhooks: []admissionv1.ValidatingWebhook{{
				ClientConfig: admissionv1.WebhookClientConfig{
					Service:  &admissionv1.ServiceReference{Name: service, Namespace: names.Namespace, Path: &path},
					CABundle: bundle,
				},
			}},
		}
	}

	tests := []struct {
		name string
		objs []runtime.Object
		want string
	}{
		{
			name: "state authority",
			objs: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: StateSecretName(domain.Name), Namespace: names.Namespace},
				Data:       map[string][]byte{activeCAKeyKey: []byte("surviving private authority")},
			}},
			want: StateSecretName(domain.Name),
		},
		{
			name: "production named trust",
			objs: []runtime.Object{
				configuration("webhooks", names.WebhookService, []byte("surviving-production-ca")),
				configuration("canary-webhooks", names.WebhookCanaryService, nil),
			},
			want: "webhooks retains a CA bundle",
		},
		{
			name: "same named mutating trust",
			objs: []runtime.Object{
				configuration("webhooks", names.WebhookService, nil),
				&admissionv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "webhooks"}, Webhooks: []admissionv1.MutatingWebhook{{ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{Name: names.WebhookService, Namespace: names.Namespace, Path: &path}, CABundle: []byte("surviving-mutating-ca"),
				}}}},
				configuration("canary-webhooks", names.WebhookCanaryService, nil),
			},
			want: "webhooks retains a CA bundle",
		},
		{
			name: "canary named trust",
			objs: []runtime.Object{
				configuration("webhooks", names.WebhookService, nil),
				configuration("canary-webhooks", names.WebhookCanaryService, []byte("surviving-candidate-ca")),
			},
			want: "canary-webhooks retains a CA bundle",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := Issuer{Client: fake.NewSimpleClientset(tt.objs...), Names: names}
			err := issuer.GuardBootstrap(context.Background(), domain)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("GuardBootstrap() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestIssuerBootstrapGuardAllowsEmptyFixedPlaceholders(t *testing.T) {
	names := Names{
		Namespace: "system", WebhookSecret: "webhook", WebhookService: "manager",
		WebhookCanarySecret: "webhook-canary", WebhookCanaryService: "manager-canary", WebhookCanaryConfiguration: "canary-webhooks",
		WebhookConfigurationNames: []string{"webhooks"},
	}
	path := "/validate"
	issuer := Issuer{Client: fake.NewSimpleClientset(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: StateSecretName("webhook"), Namespace: names.Namespace}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: names.WebhookSecret, Namespace: names.Namespace}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: names.WebhookCanarySecret, Namespace: names.Namespace}},
		&admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "webhooks"}, Webhooks: []admissionv1.ValidatingWebhook{{ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: names.WebhookService, Namespace: names.Namespace, Path: &path}}}}},
		&admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "canary-webhooks"}, Webhooks: []admissionv1.ValidatingWebhook{{ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: names.WebhookCanaryService, Namespace: names.Namespace, Path: &path}}}}},
	), Names: names}
	domain := rotation.Domain{Name: "webhook", Profile: rotation.ProfileWebhook, ConfigurationHash: "sha256:config", Policy: rotation.DefaultPolicy()}
	if err := issuer.GuardBootstrap(context.Background(), domain); err != nil {
		t.Fatalf("GuardBootstrap() error = %v for empty fixed placeholders", err)
	}
}

func TestIssuerRejectsCandidateOutsideDualTrustBundle(t *testing.T) {
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	active, err := pki.IssueRoot(pki.RootOptions{CommonName: "active", Validity: 365 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := pki.IssueRoot(pki.RootOptions{CommonName: "candidate", Validity: 365 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	activeRoot := rootFromMaterial(active)
	candidateRoot := rootFromMaterial(candidate)
	issuer := Issuer{
		Client: fake.NewSimpleClientset(),
		Names: Names{
			Namespace: "system", WebhookSecret: "webhook", WebhookService: "manager",
			WebhookCanarySecret: "webhook-canary", WebhookCanaryService: "manager-canary", WebhookCanaryConfiguration: "canary-config",
		},
		Now: func() time.Time { return now },
	}
	_, err = issuer.Issue(context.Background(), rotation.IssueRequest{
		Domain: rotation.Domain{Name: "webhook", Profile: rotation.ProfileWebhook, ConfigurationHash: "sha256:config", Policy: rotation.DefaultPolicy()},
		Signer: activeRoot, Candidate: &candidateRoot, TrustRoots: []rotation.Root{activeRoot}, DualTrust: true,
		Generation: 2, OperationID: "dual-trust",
	})
	if err == nil {
		t.Fatal("issuer accepted a candidate excluded from the dual-trust bundle")
	}
}

func parseTestLeaf(t *testing.T, data map[string][]byte) *pki.LeafMaterial {
	t.Helper()
	leaf, err := pki.ParseLeafPEM(data["tls.crt"], data["tls.key"])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func bundleFingerprintFromPEM(t *testing.T, bundle []byte) string {
	t.Helper()
	roots, err := pki.ParseCertificatesPEM(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return bundleFingerprint(roots)
}
