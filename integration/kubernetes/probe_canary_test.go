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
	"k8s.io/client-go/kubernetes/fake"

	"github.com/zeisthq/zeist-pki/pki"
	"github.com/zeisthq/zeist-pki/rotation"
)

func TestProbeWebhookRejectsCandidateSecretBeforeDryRun(t *testing.T) {
	now := time.Now().UTC()
	active, err := pki.IssueRoot(pki.RootOptions{CommonName: "active", Validity: 365 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := pki.IssueRoot(pki.RootOptions{CommonName: "candidate", Validity: 365 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	productionBundle, err := pki.EncodeCertificatesPEM(active.Certificate, candidate.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	canaryBundle, err := pki.EncodeCertificatePEM(candidate.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	canaryLeaf, err := pki.IssueLeaf(candidate, pki.LeafOptions{
		CommonName: "manager-canary.system.svc", Profile: pki.ProfileWebhook,
		DNSNames: []string{"manager-canary.system.svc", "manager-canary.system.svc.cluster.local"}, Validity: 24 * time.Hour, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := "/pki-rotation-canary"
	client := fake.NewSimpleClientset(
		&admissionv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "webhooks"},
			Webhooks: []admissionv1.MutatingWebhook{{
				ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "manager", Namespace: "system", Path: &path}, CABundle: productionBundle},
			}},
		},
		&admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "canary-webhooks"},
			Webhooks: []admissionv1.ValidatingWebhook{{
				ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "manager-canary", Namespace: "system", Path: &path}, CABundle: canaryBundle},
			}},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "webhook-canary", Namespace: "system", Annotations: map[string]string{
				annotationLeafFingerprint: "sha256:wrong", annotationTrustFingerprint: bundleFingerprint([]*x509.Certificate{candidate.Certificate}),
			}},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{"tls.crt": canaryLeaf.CertificatePEM, "tls.key": canaryLeaf.PrivateKeyPEM},
		},
	)
	names := Names{
		Namespace: "system", WebhookSecret: "webhook", WebhookService: "manager",
		WebhookCanarySecret: "webhook-canary", WebhookCanaryService: "manager-canary", WebhookCanaryConfiguration: "canary-webhooks",
		WebhookConfigurationNames: []string{"webhooks"},
	}
	productionRoots, err := pki.ParseCertificatesPEM(productionBundle)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	err = probeWebhook(context.Background(), client, names, rotation.VerificationRequest{Publication: rotation.Publication{Materials: map[string]rotation.MaterialFingerprint{
		"webhook": {TrustFingerprint: bundleFingerprint(productionRoots)},
		"canary":  {LeafFingerprint: certificateFingerprint(canaryLeaf.Certificate), TrustFingerprint: bundleFingerprint([]*x509.Certificate{candidate.Certificate})},
	}}}, func(context.Context) error {
		called = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "published fingerprint annotations") {
		t.Fatalf("probe error = %v, want candidate fingerprint rejection", err)
	}
	if called {
		t.Fatal("dry-run canary ran before candidate Secret verification")
	}
}
