//go:build envtest

package kubernetes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/zeisthq/zeist-pki/pki"
	"github.com/zeisthq/zeist-pki/rotation"
)

var envtestClient kubernetes.Interface

func TestMain(m *testing.M) {
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		fmt.Fprintln(os.Stderr, "envtest integration tests require KUBEBUILDER_ASSETS; install Kubernetes 1.36 assets with setup-envtest and set it to the returned path")
		os.Exit(2)
	}

	environment := &envtest.Environment{
		BinaryAssetsDirectory:    assets,
		ControlPlaneStartTimeout: time.Minute,
		ControlPlaneStopTimeout:  time.Minute,
		AttachControlPlaneOutput: os.Getenv("KUBEBUILDER_ATTACH_CONTROL_PLANE_OUTPUT") == "true",
	}
	config, err := environment.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "start envtest control plane with KUBEBUILDER_ASSETS=%q: %v\n", assets, err)
		os.Exit(1)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		_ = environment.Stop()
		fmt.Fprintf(os.Stderr, "build envtest Kubernetes client: %v\n", err)
		os.Exit(1)
	}
	envtestClient = client

	code := m.Run()
	if err := environment.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "stop envtest control plane: %v\n", err)
		code = 1
	}
	os.Exit(code)
}

func TestEnvtestStateStoreFencesSecretResourceVersion(t *testing.T) {
	ctx := envtestContext(t)
	namespace := createEnvtestNamespace(t, ctx, "pki-envtest-state")
	root, err := pki.IssueRoot(pki.RootOptions{CommonName: "envtest state root", Validity: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	state := rotation.State{
		SchemaVersion:     rotation.StateSchemaVersion,
		ConfigurationHash: "sha256:envtest-state",
		Phase:             rotation.PhaseStable,
		Active:            rootFromMaterial(root),
	}
	store := StateStore{Client: envtestClient, Namespace: namespace}
	created, err := store.Save(ctx, "webhook", state, "")
	if err != nil {
		t.Fatalf("create state Secret: %v", err)
	}
	if created.Version == "" || created.Version == stateVersionPrefix {
		t.Fatalf("created state has no API-server resourceVersion: %#v", created)
	}

	secret, err := envtestClient.CoreV1().Secrets(namespace).Get(ctx, StateSecretName("webhook"), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get persisted state Secret: %v", err)
	}
	beforeExternalUpdate := secret.ResourceVersion
	secret.Annotations = map[string]string{"external.example/revision": "changed"}
	secret, err = envtestClient.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("externally update state Secret: %v", err)
	}
	if secret.ResourceVersion == beforeExternalUpdate {
		t.Fatalf("API server did not advance Secret resourceVersion after update: %q", secret.ResourceVersion)
	}
	if _, err := store.Save(ctx, "webhook", state, created.Version); !errors.Is(err, rotation.ErrConflict) {
		t.Fatalf("save with stale resourceVersion error = %v, want ErrConflict", err)
	}
}

func TestEnvtestLockerAcquiresAndReleasesNamedLease(t *testing.T) {
	ctx := envtestContext(t)
	namespace := createEnvtestNamespace(t, ctx, "pki-envtest-lock")
	locker := Locker{
		Client:        envtestClient,
		Namespace:     namespace,
		Identity:      "envtest-worker",
		Duration:      time.Minute,
		RenewInterval: 30 * time.Second,
	}
	lock, err := locker.Acquire(ctx, "webhook")
	if err != nil {
		t.Fatalf("acquire named Lease: %v", err)
	}
	lease, err := envtestClient.CoordinationV1().Leases(namespace).Get(ctx, "zeist-pki-webhook", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get acquired Lease: %v", err)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != locker.Identity || lease.Spec.AcquireTime == nil || lease.Spec.RenewTime == nil {
		t.Fatalf("acquired Lease does not contain expected ownership evidence: %#v", lease.Spec)
	}
	if err := lock.Release(ctx); err != nil {
		t.Fatalf("release named Lease: %v", err)
	}
	released, err := envtestClient.CoordinationV1().Leases(namespace).Get(ctx, "zeist-pki-webhook", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get released Lease: %v", err)
	}
	if released.Spec.HolderIdentity != nil || released.Spec.AcquireTime != nil || released.Spec.RenewTime != nil {
		t.Fatalf("released Lease retains ownership evidence: %#v", released.Spec)
	}
}

func TestEnvtestDiscoveryAndVerifierUseCurrentNodePodAndLeaseEvidence(t *testing.T) {
	ctx := envtestContext(t)
	namespace := createEnvtestNamespace(t, ctx, "pki-envtest-evidence")
	node, err := envtestClient.CoreV1().Nodes().Create(ctx, &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "pki-envtest-node", Labels: map[string]string{"pki.zeist.io/envtest": "true"}},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create Node: %v", err)
	}
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.20"}}
	node, err = envtestClient.CoreV1().Nodes().UpdateStatus(ctx, node, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("set Node InternalIP: %v", err)
	}
	manager := createReadyEnvtestPod(t, ctx, namespace, "pki-envtest-manager", "", map[string]string{"app": "manager"})
	zeistd := createReadyEnvtestPod(t, ctx, namespace, "pki-envtest-zeistd", node.Name, map[string]string{"app": "zeistd"})

	names := Names{
		Namespace:                namespace,
		AcknowledgementNamespace: namespace,
		ManagerPodSelector:       "app=manager",
		ZeistdPodSelector:        "app=zeistd",
		NodeSelector:             map[string]string{"pki.zeist.io/envtest": "true"},
	}
	targets, err := (Discoverer{Client: envtestClient, Names: names}).Discover(ctx, rotation.Domain{Name: "mtls"})
	if err != nil {
		t.Fatalf("discover current targets: %v", err)
	}
	if !hasEnvtestTarget(targets, "manager:"+string(manager.UID), "client") || !hasEnvtestTarget(targets, "node:"+string(node.UID), "server") {
		t.Fatalf("discovered targets = %#v, want current manager Pod and Node UIDs", targets)
	}

	request := rotation.VerificationRequest{
		Domain:     rotation.Domain{Name: "mtls"},
		Generation: 7,
		Targets:    targets,
		Publication: rotation.Publication{Materials: map[string]rotation.MaterialFingerprint{
			"client": {LeafFingerprint: "client-leaf", TrustFingerprint: "client-trust"},
			"server": {LeafFingerprint: "server-leaf", TrustFingerprint: "server-trust"},
		}},
	}
	for _, target := range targets {
		material, found := request.Publication.MaterialFor(target)
		if !found {
			t.Fatalf("publication has no material for target %#v", target)
		}
		holder := string(manager.UID)
		if target.Evidence["role"] == "server" {
			holder = string(zeistd.UID)
		}
		acknowledgement, err := EncodeAcknowledgement(AcknowledgementLeaseData{
			Generation:       request.Generation,
			LeafFingerprint:  material.LeafFingerprint,
			TrustFingerprint: material.TrustFingerprint,
		})
		if err != nil {
			t.Fatal(err)
		}
		duration := int32(60)
		renewedAt := metav1.NewMicroTime(time.Now().UTC())
		_, err = envtestClient.CoordinationV1().Leases(namespace).Create(ctx, &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{
				Name:        AcknowledgementLeaseName(request.Domain.Name, target.ID),
				Annotations: map[string]string{acknowledgementAnnotation: acknowledgement},
			},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       &holder,
				LeaseDurationSeconds: &duration,
				RenewTime:            &renewedAt,
			},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("create acknowledgement Lease for %q: %v", target.ID, err)
		}
	}

	acknowledgements, err := (Verifier{Client: envtestClient, Names: names}).Verify(ctx, request)
	if err != nil {
		t.Fatalf("verify current acknowledgement evidence: %v", err)
	}
	if len(acknowledgements) != 2 {
		t.Fatalf("acknowledgements = %#v, want manager and node evidence", acknowledgements)
	}
}

func TestEnvtestPublisherWritesSecretsAndNamedWebhookConfigurations(t *testing.T) {
	ctx := envtestContext(t)
	namespace := createEnvtestNamespace(t, ctx, "pki-envtest-publish")
	path := "/validate"
	productionName := "pki-envtest-webhooks"
	canaryName := "pki-envtest-canary-webhooks"
	if _, err := envtestClient.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(ctx, envtestMutatingWebhookConfiguration(productionName, namespace, "webhook", path), metav1.CreateOptions{}); err != nil {
		t.Fatalf("create production mutating webhook configuration: %v", err)
	}
	if _, err := envtestClient.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(ctx, envtestValidatingWebhookConfiguration(productionName, namespace, "webhook", path), metav1.CreateOptions{}); err != nil {
		t.Fatalf("create production validating webhook configuration: %v", err)
	}
	if _, err := envtestClient.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(ctx, envtestValidatingWebhookConfiguration(canaryName, namespace, "webhook-canary", path), metav1.CreateOptions{}); err != nil {
		t.Fatalf("create canary validating webhook configuration: %v", err)
	}

	publisher := Publisher{Client: envtestClient, Names: Names{
		Namespace:                  namespace,
		WebhookSecret:              "webhook",
		WebhookService:             "webhook",
		WebhookCanarySecret:        "webhook-canary",
		WebhookCanaryService:       "webhook-canary",
		WebhookCanaryConfiguration: canaryName,
		WebhookConfigurationNames:  []string{productionName},
	}}
	publication := rotation.Publication{
		Domain:      "webhook",
		Generation:  7,
		OperationID: "envtest-publication",
		Materials: map[string]rotation.MaterialFingerprint{
			"webhook": {LeafFingerprint: "webhook-leaf", TrustFingerprint: "production-trust"},
			"canary":  {LeafFingerprint: "canary-leaf", TrustFingerprint: "candidate-trust"},
		},
		Opaque: PublicationMaterial{
			WebhookTLS:        map[string][]byte{"tls.crt": []byte("webhook-cert"), "tls.key": []byte("webhook-key")},
			WebhookCanaryTLS:  map[string][]byte{"tls.crt": []byte("canary-cert"), "tls.key": []byte("canary-key")},
			TrustBundle:       []byte("production-trust"),
			CanaryTrustBundle: []byte("candidate-trust"),
		},
	}
	if err := publisher.Publish(ctx, publication); err != nil {
		t.Fatalf("publish webhook materials: %v", err)
	}

	secret, err := envtestClient.CoreV1().Secrets(namespace).Get(ctx, "webhook", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get production webhook Secret: %v", err)
	}
	if secret.Type != corev1.SecretTypeTLS || !bytes.Equal(secret.Data["tls.crt"], []byte("webhook-cert")) || secret.Annotations[annotationGeneration] != "7" {
		t.Fatalf("published production Secret = %#v", secret)
	}
	canarySecret, err := envtestClient.CoreV1().Secrets(namespace).Get(ctx, "webhook-canary", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get canary webhook Secret: %v", err)
	}
	if canarySecret.Type != corev1.SecretTypeTLS || !bytes.Equal(canarySecret.Data["tls.crt"], []byte("canary-cert")) || canarySecret.Annotations[annotationLeafFingerprint] != "canary-leaf" {
		t.Fatalf("published canary Secret = %#v", canarySecret)
	}
	mutating, err := envtestClient.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, productionName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get production mutating configuration: %v", err)
	}
	validating, err := envtestClient.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, productionName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get production validating configuration: %v", err)
	}
	canary, err := envtestClient.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, canaryName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get canary validating configuration: %v", err)
	}
	if !bytes.Equal(mutating.Webhooks[0].ClientConfig.CABundle, []byte("production-trust")) || !bytes.Equal(validating.Webhooks[0].ClientConfig.CABundle, []byte("production-trust")) || !bytes.Equal(canary.Webhooks[0].ClientConfig.CABundle, []byte("candidate-trust")) {
		t.Fatalf("published webhook trust bundles = mutating:%q validating:%q canary:%q", mutating.Webhooks[0].ClientConfig.CABundle, validating.Webhooks[0].ClientConfig.CABundle, canary.Webhooks[0].ClientConfig.CABundle)
	}
}

func envtestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func createEnvtestNamespace(t *testing.T, ctx context.Context, name string) string {
	t.Helper()
	if _, err := envtestClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace %q: %v", name, err)
	}
	return name
}

func createReadyEnvtestPod(t *testing.T, ctx context.Context, namespace, name, nodeName string, labels map[string]string) *corev1.Pod {
	t.Helper()
	pod, err := envtestClient.CoreV1().Pods(namespace).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
			Containers: []corev1.Container{{
				Name:  "holder",
				Image: "registry.k8s.io/pause:3.10",
			}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create Pod %q: %v", name, err)
	}
	pod.Status = corev1.PodStatus{
		Phase: corev1.PodRunning,
		Conditions: []corev1.PodCondition{{
			Type:               corev1.PodReady,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
		}},
	}
	pod, err = envtestClient.CoreV1().Pods(namespace).UpdateStatus(ctx, pod, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("mark Pod %q Ready: %v", name, err)
	}
	return pod
}

func hasEnvtestTarget(targets []rotation.Target, id, role string) bool {
	for _, target := range targets {
		if target.ID == id && target.Evidence["role"] == role {
			return true
		}
	}
	return false
}

func envtestMutatingWebhookConfiguration(name, namespace, service, path string) *admissionv1.MutatingWebhookConfiguration {
	failurePolicy := admissionv1.Ignore
	sideEffects := admissionv1.SideEffectClassNone
	return &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:                    name + ".pki.zeist.io",
			FailurePolicy:           &failurePolicy,
			SideEffects:             &sideEffects,
			AdmissionReviewVersions: []string{"v1"},
			Rules:                   envtestWebhookRules(),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: &admissionv1.ServiceReference{Name: service, Namespace: namespace, Path: &path},
			},
		}},
	}
}

func envtestValidatingWebhookConfiguration(name, namespace, service, path string) *admissionv1.ValidatingWebhookConfiguration {
	failurePolicy := admissionv1.Ignore
	sideEffects := admissionv1.SideEffectClassNone
	return &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name:                    name + ".pki.zeist.io",
			FailurePolicy:           &failurePolicy,
			SideEffects:             &sideEffects,
			AdmissionReviewVersions: []string{"v1"},
			Rules:                   envtestWebhookRules(),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: &admissionv1.ServiceReference{Name: service, Namespace: namespace, Path: &path},
			},
		}},
	}
}

func envtestWebhookRules() []admissionv1.RuleWithOperations {
	// The envtest API server persists real admission configuration, but it does
	// not run a Service data plane. Keep this rule on the Zeist CRD group,
	// which this focused suite does not install, so its placeholder Service is
	// never called while ordinary API operations remain usable.
	return []admissionv1.RuleWithOperations{{
		Operations: []admissionv1.OperationType{admissionv1.Create},
		Rule: admissionv1.Rule{
			APIGroups:   []string{"sandbox.zeist.io"},
			APIVersions: []string{"v1alpha1"},
			Resources:   []string{"sandboxpools"},
		},
	}}
}
