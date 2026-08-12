package kubernetes

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/zeisthq/zeist-pki/pki"
	"github.com/zeisthq/zeist-pki/rotation"
)

func TestRecovererAdoptsConfirmedMTLSLeavesOnlyForDualTrust(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	active, err := pki.IssueRoot(pki.RootOptions{CommonName: "active", Validity: 365 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := pki.EncodeCertificatePEM(active.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	server, serverFingerprint, _, err := issueOutput(active, pki.LeafOptions{
		CommonName: "zeistd", Profile: pki.ProfileServer,
		DNSNames: []string{"zeistd.system.svc"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.9")},
		Validity: 90 * 24 * time.Hour, Now: now,
	}, trust, "sha256:old")
	if err != nil {
		t.Fatal(err)
	}
	client, clientFingerprint, _, err := issueOutput(active, pki.LeafOptions{
		CommonName: "zeist-controller", Profile: pki.ProfileClient, Validity: 90 * 24 * time.Hour, Now: now,
	}, trust, "sha256:old")
	if err != nil {
		t.Fatal(err)
	}
	trustFingerprint := bundleFingerprint([]*x509.Certificate{active.Certificate})
	annotations := func(leafFingerprint string) map[string]string {
		return map[string]string{
			annotationDomain:           "mtls",
			annotationGeneration:       "4",
			annotationOperation:        "legacy-operation",
			annotationLeafFingerprint:  leafFingerprint,
			annotationTrustFingerprint: trustFingerprint,
		}
	}
	cluster := fake.NewSimpleClientset(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "server", Namespace: "system", Annotations: annotations(serverFingerprint)}, Type: corev1.SecretTypeTLS, Data: server},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "system", Annotations: annotations(clientFingerprint)}, Type: corev1.SecretTypeTLS, Data: client},
	)
	names := Names{Namespace: "system", ServerSecret: "server", ClientSecret: "client"}
	policy := rotation.DefaultPolicy()
	domain := rotation.Domain{Name: "mtls", Profile: rotation.ProfileMTLS, ConfigurationHash: "sha256:config", Policy: policy}
	store := StateStore{Client: cluster, Namespace: names.Namespace}
	issuer := Issuer{Client: cluster, Names: names, Now: func() time.Time { return now }}
	recoverer := Recoverer{Client: cluster, Store: store, Locker: recoveryTestLocker(cluster, names.Namespace), Issuer: issuer, Names: names, Now: func() time.Time { return now }}

	result, err := recoverer.Recover(ctx, domain, certificateFingerprint(active.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	if result.State.Phase != rotation.PhasePublishingDualTrust || !result.State.ActiveKeyUnavailable || result.State.Candidate == nil {
		t.Fatalf("recovery state = %#v", result.State)
	}
	lease, err := cluster.CoordinationV1().Leases("system").Get(ctx, "zeist-pki-mtls", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read released recovery lease: %v", err)
	}
	if lease.Spec.HolderIdentity != nil {
		t.Fatalf("recovery lease holder = %q, want released", *lease.Spec.HolderIdentity)
	}
	stateSecret, err := cluster.CoreV1().Secrets("system").Get(ctx, StateSecretName("mtls"), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stateSecret.Data[activeCAKeyKey]) != 0 || len(stateSecret.Data[candidateCAKeyKey]) == 0 {
		t.Fatalf("recovery authority material has active=%d candidate=%d private bytes", len(stateSecret.Data[activeCAKeyKey]), len(stateSecret.Data[candidateCAKeyKey]))
	}

	loaded, err := store.Load(ctx, domain.Name)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := issuer.Issue(ctx, rotation.IssueRequest{
		Domain: domain, Signer: *loaded.State.Candidate, Candidate: loaded.State.Candidate, TrustRoots: []rotation.Root{loaded.State.Active, *loaded.State.Candidate},
		DualTrust: true, ReuseExistingLeaves: true, Generation: loaded.State.DesiredGeneration, OperationID: loaded.State.OperationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	publication.Domain = domain.Name
	publication.Generation = loaded.State.DesiredGeneration
	publication.OperationID = loaded.State.OperationID
	publication.DualTrust = true
	publication.AdoptExisting = true
	if err := (Publisher{Client: cluster, Names: names}).Publish(ctx, publication); err != nil {
		t.Fatal(err)
	}

	for name, original := range map[string]map[string][]byte{"server": server, "client": client} {
		secret, err := cluster.CoreV1().Secrets("system").Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(secret.Data["tls.crt"], original["tls.crt"]) || !bytes.Equal(secret.Data["tls.key"], original["tls.key"]) {
			t.Fatalf("recovery replaced %s leaf credentials", name)
		}
		roots, err := pki.ParseCertificatesPEM(secret.Data["ca.crt"])
		if err != nil {
			t.Fatal(err)
		}
		if len(roots) != 2 {
			t.Fatalf("%s trust roots = %d, want dual trust", name, len(roots))
		}
	}
}

func TestRecovererRejectsMixedOrInconsistentOutputFences(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	root, err := pki.IssueRoot(pki.RootOptions{CommonName: "root", Validity: 365 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := pki.EncodeCertificatePEM(root.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	server, serverFingerprint, _, err := issueOutput(root, pki.LeafOptions{
		CommonName: "zeistd", Profile: pki.ProfileServer, DNSNames: []string{"zeistd.system.svc"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.9")}, Validity: 90 * 24 * time.Hour, Now: now,
	}, trust, "unused")
	if err != nil {
		t.Fatal(err)
	}
	client, clientFingerprint, _, err := issueOutput(root, pki.LeafOptions{
		CommonName: "zeist-controller", Profile: pki.ProfileClient, Validity: 90 * 24 * time.Hour, Now: now,
	}, trust, "unused")
	if err != nil {
		t.Fatal(err)
	}
	trustFingerprint := bundleFingerprint([]*x509.Certificate{root.Certificate})
	domain := rotation.Domain{Name: "mtls", Profile: rotation.ProfileMTLS, ConfigurationHash: "sha256:config", Policy: rotation.DefaultPolicy()}
	names := Names{Namespace: "system", ServerSecret: "server", ClientSecret: "client"}

	tests := []struct {
		name              string
		serverAnnotations map[string]string
		clientAnnotations map[string]string
	}{
		{
			name:              "mixed managed and legacy outputs",
			serverAnnotations: recoveryOutputAnnotations("mtls", 4, "operation", serverFingerprint, trustFingerprint),
		},
		{
			name:              "different operation identities",
			serverAnnotations: recoveryOutputAnnotations("mtls", 4, "operation-a", serverFingerprint, trustFingerprint),
			clientAnnotations: recoveryOutputAnnotations("mtls", 4, "operation-b", clientFingerprint, trustFingerprint),
		},
		{
			name:              "mismatched published leaf fingerprint",
			serverAnnotations: recoveryOutputAnnotations("mtls", 4, "operation", "sha256:wrong", trustFingerprint),
			clientAnnotations: recoveryOutputAnnotations("mtls", 4, "operation", clientFingerprint, trustFingerprint),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster := fake.NewSimpleClientset(
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "server", Namespace: "system", Annotations: tt.serverAnnotations}, Type: corev1.SecretTypeTLS, Data: cloneData(server)},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "system", Annotations: tt.clientAnnotations}, Type: corev1.SecretTypeTLS, Data: cloneData(client)},
			)
			recoverer := Recoverer{Client: cluster, Store: StateStore{Client: cluster, Namespace: names.Namespace}, Locker: recoveryTestLocker(cluster, names.Namespace), Issuer: Issuer{Client: cluster, Names: names, Now: func() time.Time { return now }}, Names: names, Now: func() time.Time { return now }}
			if _, err := recoverer.Recover(ctx, domain, certificateFingerprint(root.Certificate)); err == nil {
				t.Fatal("recovery accepted inconsistent output fencing")
			}
			if _, err := cluster.CoreV1().Secrets("system").Get(ctx, StateSecretName("mtls"), metav1.GetOptions{}); err == nil {
				t.Fatal("recovery persisted state after rejecting inconsistent output fencing")
			}
		})
	}
}

func recoveryOutputAnnotations(domain string, generation uint64, operation, leaf, trust string) map[string]string {
	return map[string]string{
		annotationDomain: domain, annotationGeneration: fmt.Sprintf("%d", generation), annotationOperation: operation,
		annotationLeafFingerprint: leaf, annotationTrustFingerprint: trust,
	}
}

func TestRecovererRejectsUnconfirmedRoot(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	root, err := pki.IssueRoot(pki.RootOptions{CommonName: "root", Validity: 365 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := pki.EncodeCertificatePEM(root.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	server, _, _, err := issueOutput(root, pki.LeafOptions{CommonName: "zeistd", Profile: pki.ProfileServer, DNSNames: []string{"zeistd.system.svc"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.9")}, Validity: 90 * 24 * time.Hour, Now: now}, trust, "sha256:old")
	if err != nil {
		t.Fatal(err)
	}
	clientLeaf, _, _, err := issueOutput(root, pki.LeafOptions{CommonName: "zeist-controller", Profile: pki.ProfileClient, Validity: 90 * 24 * time.Hour, Now: now}, trust, "sha256:old")
	if err != nil {
		t.Fatal(err)
	}
	cluster := fake.NewSimpleClientset(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "server", Namespace: "system"}, Data: server},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "system"}, Data: clientLeaf},
	)
	names := Names{Namespace: "system", ServerSecret: "server", ClientSecret: "client"}
	domain := rotation.Domain{Name: "mtls", Profile: rotation.ProfileMTLS, ConfigurationHash: "sha256:config", Policy: rotation.DefaultPolicy()}
	recoverer := Recoverer{Client: cluster, Store: StateStore{Client: cluster, Namespace: "system"}, Locker: recoveryTestLocker(cluster, names.Namespace), Issuer: Issuer{Client: cluster, Names: names, Now: func() time.Time { return now }}, Names: names, Now: func() time.Time { return now }}
	if _, err := recoverer.Recover(ctx, domain, "sha256:not-the-root"); err == nil {
		t.Fatal("recovery accepted an unconfirmed root")
	}
	if _, err := cluster.CoreV1().Secrets("system").Get(ctx, StateSecretName("mtls"), metav1.GetOptions{}); err == nil {
		t.Fatal("recovery persisted state after rejecting confirmation")
	}
}

func TestRecovererRejectsInvalidOrExpiredExtraMTLSTrustRoot(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		extra func(*testing.T, *pki.RootMaterial, time.Time) *x509.Certificate
	}{
		{
			name: "non CA certificate",
			extra: func(t *testing.T, active *pki.RootMaterial, now time.Time) *x509.Certificate {
				t.Helper()
				leaf, err := pki.IssueLeaf(active, pki.LeafOptions{CommonName: "not-a-root", Profile: pki.ProfileClient, Validity: 90 * 24 * time.Hour, Now: now})
				if err != nil {
					t.Fatal(err)
				}
				return leaf.Certificate
			},
		},
		{
			name: "expired root",
			extra: func(t *testing.T, _ *pki.RootMaterial, now time.Time) *x509.Certificate {
				t.Helper()
				expired, err := pki.IssueRoot(pki.RootOptions{CommonName: "expired", Validity: 365 * 24 * time.Hour, Now: now.AddDate(-2, 0, 0)})
				if err != nil {
					t.Fatal(err)
				}
				return expired.Certificate
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			active, err := pki.IssueRoot(pki.RootOptions{CommonName: "active", Validity: 365 * 24 * time.Hour, Now: now})
			if err != nil {
				t.Fatal(err)
			}
			trust := recoveryTrustBundle(t, active.Certificate, tt.extra(t, active, now))
			server, _, _, err := issueOutput(active, pki.LeafOptions{
				CommonName: "zeistd", Profile: pki.ProfileServer,
				DNSNames: []string{"zeistd.system.svc"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.9")},
				Validity: 90 * 24 * time.Hour, Now: now,
			}, trust, "sha256:legacy")
			if err != nil {
				t.Fatal(err)
			}
			client, _, _, err := issueOutput(active, pki.LeafOptions{CommonName: "zeist-controller", Profile: pki.ProfileClient, Validity: 90 * 24 * time.Hour, Now: now}, trust, "sha256:legacy")
			if err != nil {
				t.Fatal(err)
			}
			names := Names{Namespace: "system", ServerSecret: "server", ClientSecret: "client"}
			cluster := fake.NewSimpleClientset(
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: names.ServerSecret, Namespace: names.Namespace}, Data: server},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: names.ClientSecret, Namespace: names.Namespace}, Data: client},
			)
			domain := rotation.Domain{Name: "mtls", Profile: rotation.ProfileMTLS, ConfigurationHash: "sha256:config", Policy: rotation.DefaultPolicy()}
			recoverer := Recoverer{Client: cluster, Store: StateStore{Client: cluster, Namespace: names.Namespace}, Locker: recoveryTestLocker(cluster, names.Namespace), Issuer: Issuer{Client: cluster, Names: names, Now: func() time.Time { return now }}, Names: names, Now: func() time.Time { return now }}

			if _, err := recoverer.Recover(ctx, domain, certificateFingerprint(active.Certificate)); err == nil {
				t.Fatal("recovery accepted an invalid extra mTLS trust root")
			}
			if _, err := cluster.CoreV1().Secrets(names.Namespace).Get(ctx, StateSecretName(domain.Name), metav1.GetOptions{}); err == nil {
				t.Fatal("recovery persisted state after rejecting an invalid extra mTLS trust root")
			}
		})
	}
}

func TestRecovererRejectsExpiredExtraWebhookTrustRoot(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	active, err := pki.IssueRoot(pki.RootOptions{CommonName: "active", Validity: 365 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	expired, err := pki.IssueRoot(pki.RootOptions{CommonName: "expired", Validity: 365 * 24 * time.Hour, Now: now.AddDate(-2, 0, 0)})
	if err != nil {
		t.Fatal(err)
	}
	primary, _, _, err := issueOutput(active, pki.LeafOptions{
		CommonName: "manager.system.svc", Profile: pki.ProfileWebhook,
		DNSNames: []string{"manager.system.svc", "manager.system.svc.cluster.local"}, Validity: 90 * 24 * time.Hour, Now: now,
	}, nil, "sha256:legacy")
	if err != nil {
		t.Fatal(err)
	}
	path := "/validate"
	names := Names{
		Namespace: "system", WebhookSecret: "webhook", WebhookService: "manager",
		WebhookCanarySecret: "webhook-canary", WebhookCanaryService: "manager-canary", WebhookCanaryConfiguration: "canary-webhooks",
		WebhookConfigurationNames: []string{"webhooks"},
	}
	cluster := fake.NewSimpleClientset(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: names.WebhookSecret, Namespace: names.Namespace}, Data: primary},
		// The empty canary output and trust bundle are the documented legacy
		// placeholder and must remain accepted independently of production-root
		// validation.
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: names.WebhookCanarySecret, Namespace: names.Namespace}},
		&admissionv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "webhooks"}, Webhooks: []admissionv1.MutatingWebhook{{
			ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: names.WebhookService, Namespace: names.Namespace, Path: &path}, CABundle: recoveryTrustBundle(t, active.Certificate, expired.Certificate)},
		}}},
		&admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: names.WebhookCanaryConfiguration}, Webhooks: []admissionv1.ValidatingWebhook{{
			ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: names.WebhookCanaryService, Namespace: names.Namespace, Path: &path}},
		}}},
	)
	domain := rotation.Domain{Name: "webhook", Profile: rotation.ProfileWebhook, ConfigurationHash: "sha256:config", Policy: rotation.DefaultPolicy()}
	recoverer := Recoverer{Client: cluster, Store: StateStore{Client: cluster, Namespace: names.Namespace}, Locker: recoveryTestLocker(cluster, names.Namespace), Issuer: Issuer{Client: cluster, Names: names, Now: func() time.Time { return now }}, Names: names, Now: func() time.Time { return now }}

	if _, err := recoverer.Recover(ctx, domain, certificateFingerprint(active.Certificate)); err == nil {
		t.Fatal("recovery accepted an expired extra webhook trust root")
	}
	if _, err := cluster.CoreV1().Secrets(names.Namespace).Get(ctx, StateSecretName(domain.Name), metav1.GetOptions{}); err == nil {
		t.Fatal("recovery persisted state after rejecting an expired extra webhook trust root")
	}
}

func recoveryTrustBundle(t *testing.T, certificates ...*x509.Certificate) []byte {
	t.Helper()
	var bundle []byte
	for _, certificate := range certificates {
		encoded, err := pki.EncodeCertificatePEM(certificate)
		if err != nil {
			t.Fatal(err)
		}
		bundle = append(bundle, encoded...)
	}
	return bundle
}

func TestRecovererRetainsPrimaryWebhookAndReplacesCanaryWithCandidateLeaf(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	active, err := pki.IssueRoot(pki.RootOptions{CommonName: "active", Validity: 365 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := pki.EncodeCertificatePEM(active.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	primary, _, _, err := issueOutput(active, pki.LeafOptions{
		CommonName: "manager.system.svc", Profile: pki.ProfileWebhook,
		DNSNames: []string{"manager.system.svc", "manager.system.svc.cluster.local"}, Validity: 90 * 24 * time.Hour, Now: now,
	}, nil, "sha256:old")
	if err != nil {
		t.Fatal(err)
	}
	canary, _, _, err := issueOutput(active, pki.LeafOptions{
		CommonName: "manager-canary.system.svc", Profile: pki.ProfileWebhook,
		DNSNames: []string{"manager-canary.system.svc", "manager-canary.system.svc.cluster.local"}, Validity: 90 * 24 * time.Hour, Now: now,
	}, nil, "sha256:old")
	if err != nil {
		t.Fatal(err)
	}
	path := "/validate"
	cluster := fake.NewSimpleClientset(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "webhook", Namespace: "system"}, Type: corev1.SecretTypeTLS, Data: primary},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "webhook-canary", Namespace: "system"}, Type: corev1.SecretTypeTLS, Data: canary},
		&admissionv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "webhooks"},
			Webhooks: []admissionv1.MutatingWebhook{{
				ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "manager", Namespace: "system", Path: &path}, CABundle: trust},
			}},
		},
		&admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "canary-webhooks"},
			Webhooks: []admissionv1.ValidatingWebhook{{
				ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "manager-canary", Namespace: "system", Path: &path}, CABundle: trust},
			}},
		},
	)
	names := Names{
		Namespace: "system", WebhookSecret: "webhook", WebhookService: "manager",
		WebhookCanarySecret: "webhook-canary", WebhookCanaryService: "manager-canary", WebhookCanaryConfiguration: "canary-webhooks",
		WebhookConfigurationNames: []string{"webhooks"},
	}
	domain := rotation.Domain{Name: "webhook", Profile: rotation.ProfileWebhook, ConfigurationHash: "sha256:config", Policy: rotation.DefaultPolicy()}
	store := StateStore{Client: cluster, Namespace: names.Namespace}
	issuer := Issuer{Client: cluster, Names: names, Now: func() time.Time { return now }}
	recoverer := Recoverer{Client: cluster, Store: store, Locker: recoveryTestLocker(cluster, names.Namespace), Issuer: issuer, Names: names, Now: func() time.Time { return now }}

	result, err := recoverer.Recover(ctx, domain, certificateFingerprint(active.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(ctx, domain.Name)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := issuer.Issue(ctx, rotation.IssueRequest{
		Domain: domain, Signer: *loaded.State.Candidate, Candidate: loaded.State.Candidate,
		TrustRoots: []rotation.Root{loaded.State.Active, *loaded.State.Candidate}, DualTrust: true, ReuseExistingLeaves: true,
		Generation: loaded.State.DesiredGeneration, OperationID: loaded.State.OperationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	publication.Domain = domain.Name
	publication.Generation = loaded.State.DesiredGeneration
	publication.OperationID = loaded.State.OperationID
	publication.DualTrust = true
	publication.AdoptExisting = true
	if err := (Publisher{Client: cluster, Names: names}).Publish(ctx, publication); err != nil {
		t.Fatal(err)
	}
	updatedPrimary, err := cluster.CoreV1().Secrets("system").Get(ctx, "webhook", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(updatedPrimary.Data["tls.crt"], primary["tls.crt"]) || !bytes.Equal(updatedPrimary.Data["tls.key"], primary["tls.key"]) {
		t.Fatal("recovery replaced the surviving production webhook leaf")
	}
	updatedCanary, err := cluster.CoreV1().Secrets("system").Get(ctx, "webhook-canary", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	canaryLeaf, err := pki.ParseLeafPEM(updatedCanary.Data["tls.crt"], updatedCanary.Data["tls.key"])
	if err != nil {
		t.Fatal(err)
	}
	candidateCertificate, err := authorityCertificate(*result.State.Candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := canaryLeaf.Certificate.CheckSignatureFrom(candidateCertificate); err != nil {
		t.Fatalf("recovery canary was not candidate-signed: %v", err)
	}
	productionConfiguration, err := cluster.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "webhooks", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	roots, err := pki.ParseCertificatesPEM(productionConfiguration.Webhooks[0].ClientConfig.CABundle)
	if err != nil || len(roots) != 2 {
		t.Fatalf("recovery production trust roots = %d, %v", len(roots), err)
	}
	canaryConfiguration, err := cluster.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, "canary-webhooks", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	canaryRoots, err := pki.ParseCertificatesPEM(canaryConfiguration.Webhooks[0].ClientConfig.CABundle)
	if err != nil || len(canaryRoots) != 1 || certificateFingerprint(canaryRoots[0]) != certificateFingerprint(candidateCertificate) {
		t.Fatalf("recovery candidate-only canary trust = %#v, %v", canaryRoots, err)
	}
}

func TestRecovererAcceptsLegacyEmptyCanaryAndPublishesCandidateProof(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	active, err := pki.IssueRoot(pki.RootOptions{CommonName: "active", Validity: 365 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := pki.EncodeCertificatePEM(active.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	primary, _, _, err := issueOutput(active, pki.LeafOptions{
		CommonName: "manager.system.svc", Profile: pki.ProfileWebhook,
		DNSNames: []string{"manager.system.svc", "manager.system.svc.cluster.local"}, Validity: 90 * 24 * time.Hour, Now: now,
	}, nil, "sha256:old")
	if err != nil {
		t.Fatal(err)
	}
	path := "/validate"
	cluster := fake.NewSimpleClientset(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "webhook", Namespace: "system"}, Type: corev1.SecretTypeTLS, Data: primary},
		// The pre-created canary Secret and VWC are intentionally empty in a
		// legacy deployment. Recovery must persist a candidate before filling
		// either one, not reject this transition as surviving material.
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "webhook-canary", Namespace: "system"}, Type: corev1.SecretTypeTLS},
		&admissionv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "webhooks"},
			Webhooks: []admissionv1.MutatingWebhook{{
				ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "manager", Namespace: "system", Path: &path}, CABundle: trust},
			}},
		},
		&admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "canary-webhooks"},
			Webhooks: []admissionv1.ValidatingWebhook{{
				ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "manager-canary", Namespace: "system", Path: &path}},
			}},
		},
	)
	names := Names{
		Namespace: "system", WebhookSecret: "webhook", WebhookService: "manager",
		WebhookCanarySecret: "webhook-canary", WebhookCanaryService: "manager-canary", WebhookCanaryConfiguration: "canary-webhooks",
		WebhookConfigurationNames: []string{"webhooks"},
	}
	domain := rotation.Domain{Name: "webhook", Profile: rotation.ProfileWebhook, ConfigurationHash: "sha256:config", Policy: rotation.DefaultPolicy()}
	store := StateStore{Client: cluster, Namespace: names.Namespace}
	issuer := Issuer{Client: cluster, Names: names, Now: func() time.Time { return now }}
	recoverer := Recoverer{Client: cluster, Store: store, Locker: recoveryTestLocker(cluster, names.Namespace), Issuer: issuer, Names: names, Now: func() time.Time { return now }}

	result, err := recoverer.Recover(ctx, domain, certificateFingerprint(active.Certificate))
	if err != nil {
		t.Fatalf("legacy recovery: %v", err)
	}
	publication, err := issuer.Issue(ctx, rotation.IssueRequest{
		Domain: domain, Signer: *result.State.Candidate, Candidate: result.State.Candidate,
		TrustRoots: []rotation.Root{result.State.Active, *result.State.Candidate}, DualTrust: true, ReuseExistingLeaves: true,
		Generation: result.State.DesiredGeneration, OperationID: result.State.OperationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	publication.Domain = domain.Name
	publication.Generation = result.State.DesiredGeneration
	publication.OperationID = result.State.OperationID
	publication.DualTrust = true
	publication.AdoptExisting = true
	if err := (Publisher{Client: cluster, Names: names}).Publish(ctx, publication); err != nil {
		t.Fatal(err)
	}
	canarySecret, err := cluster.CoreV1().Secrets("system").Get(ctx, "webhook-canary", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	canaryLeaf, err := pki.ParseLeafPEM(canarySecret.Data["tls.crt"], canarySecret.Data["tls.key"])
	if err != nil {
		t.Fatal(err)
	}
	candidateCertificate, err := authorityCertificate(*result.State.Candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := canaryLeaf.Certificate.CheckSignatureFrom(candidateCertificate); err != nil {
		t.Fatalf("legacy recovery canary was not candidate-signed: %v", err)
	}
	canaryConfiguration, err := cluster.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, "canary-webhooks", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	canaryRoots, err := pki.ParseCertificatesPEM(canaryConfiguration.Webhooks[0].ClientConfig.CABundle)
	if err != nil || len(canaryRoots) != 1 || certificateFingerprint(canaryRoots[0]) != certificateFingerprint(candidateCertificate) {
		t.Fatalf("legacy recovery candidate-only canary trust = %#v, %v", canaryRoots, err)
	}
}

func TestRecovererDoesNotInspectOrMutateWhenFenceCannotBeAcquired(t *testing.T) {
	cluster := fake.NewSimpleClientset()
	acquireErr := errors.New("another reconciler holds the lease")
	recoverer := Recoverer{
		Client: cluster,
		Store:  StateStore{Client: cluster, Namespace: "system"},
		Locker: failingRecoveryLocker{err: acquireErr},
		Issuer: Issuer{Client: cluster, Names: Names{Namespace: "system"}},
		Names:  Names{Namespace: "system", ServerSecret: "server", ClientSecret: "client"},
	}
	domain := rotation.Domain{Name: "mtls", Profile: rotation.ProfileMTLS, ConfigurationHash: "sha256:config", Policy: rotation.DefaultPolicy()}

	_, err := recoverer.Recover(context.Background(), domain, "sha256:confirmed")
	if !errors.Is(err, acquireErr) {
		t.Fatalf("recovery error = %v, want wrapped fence acquisition failure", err)
	}
	if actions := cluster.Actions(); len(actions) != 0 {
		t.Fatalf("recovery inspected or mutated Kubernetes state after fence failure: %#v", actions)
	}
}

func TestRecovererStopsWhenRenewableFenceIsLostDuringStateInspection(t *testing.T) {
	cluster := fake.NewSimpleClientset()
	lostErr := errors.New("lease renewal conflicted")
	lock := newLossAfterInitialRecoveryCheckLock(lostErr)
	locker := &fixedRecoveryLocker{lock: lock}
	recoverer := Recoverer{
		Client: cluster,
		Store:  StateStore{Client: cluster, Namespace: "system"},
		Locker: locker,
		Issuer: Issuer{Client: cluster, Names: Names{Namespace: "system"}},
		Names:  Names{Namespace: "system", ServerSecret: "server", ClientSecret: "client"},
	}
	domain := rotation.Domain{Name: "mtls", Profile: rotation.ProfileMTLS, ConfigurationHash: "sha256:config", Policy: rotation.DefaultPolicy()}

	_, err := recoverer.Recover(context.Background(), domain, "sha256:confirmed")
	if !errors.Is(err, lostErr) {
		t.Fatalf("recovery error = %v, want wrapped renewable-fence loss", err)
	}
	if locker.domain != "mtls" {
		t.Fatalf("fence acquired for %q, want domain mtls", locker.domain)
	}
	if lock.releaseCalls != 1 {
		t.Fatalf("fence releases = %d, want 1", lock.releaseCalls)
	}
	for _, action := range cluster.Actions() {
		if action.GetVerb() == "create" || action.GetVerb() == "update" || action.GetVerb() == "delete" || action.GetVerb() == "patch" {
			t.Fatalf("recovery mutated Kubernetes state after fence loss: %#v", action)
		}
	}
}

func recoveryTestLocker(client *fake.Clientset, namespace string) Locker {
	return Locker{Client: client, Namespace: namespace, Identity: "recovery-test"}
}

type failingRecoveryLocker struct{ err error }

func (l failingRecoveryLocker) Acquire(context.Context, string) (rotation.Lock, error) {
	return nil, l.err
}

type fixedRecoveryLocker struct {
	lock   rotation.Lock
	err    error
	domain string
}

func (l *fixedRecoveryLocker) Acquire(_ context.Context, domain string) (rotation.Lock, error) {
	l.domain = domain
	if l.err != nil {
		return nil, l.err
	}
	return l.lock, nil
}

type lossAfterInitialRecoveryCheckLock struct {
	ctx          context.Context
	cancel       context.CancelFunc
	err          error
	errChecks    int
	releaseCalls int
}

func newLossAfterInitialRecoveryCheckLock(err error) *lossAfterInitialRecoveryCheckLock {
	ctx, cancel := context.WithCancel(context.Background())
	return &lossAfterInitialRecoveryCheckLock{ctx: ctx, cancel: cancel, err: err}
}

func (l *lossAfterInitialRecoveryCheckLock) Context() context.Context { return l.ctx }

func (l *lossAfterInitialRecoveryCheckLock) Err() error {
	l.errChecks++
	if l.errChecks < 2 {
		return nil
	}
	l.cancel()
	return l.err
}

func (l *lossAfterInitialRecoveryCheckLock) Release(context.Context) error {
	l.releaseCalls++
	l.cancel()
	return nil
}
