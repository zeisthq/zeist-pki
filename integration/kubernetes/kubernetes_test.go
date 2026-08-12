package kubernetes

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/zeisthq/zeist-pki/pki"
	"github.com/zeisthq/zeist-pki/rotation"
)

func TestStateStoreFencesConflictingWrites(t *testing.T) {
	client := fake.NewSimpleClientset()
	store := StateStore{Client: client, Namespace: "system"}
	root, err := pki.IssueRoot(pki.RootOptions{CommonName: "test root", Validity: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	state := rotation.State{SchemaVersion: rotation.StateSchemaVersion, ConfigurationHash: "sha256:state", Phase: rotation.PhaseStable, Active: rootFromMaterial(root)}
	created, err := store.Save(context.Background(), "webhook", state, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(context.Background(), "webhook", state, "wrong"); err != rotation.ErrConflict {
		t.Fatalf("conflicting save = %v, want ErrConflict", err)
	}
	// The fake client does not assign a resource version during Create. Obtain
	// the authoritative current version just as a real reconciler does after a
	// successful write before testing the optimistic update path.
	loaded, err := store.Load(context.Background(), "webhook")
	if err != nil {
		t.Fatal(err)
	}
	if created.Version != loaded.Version {
		t.Fatalf("created version %q differs from loaded version %q", created.Version, loaded.Version)
	}
	if _, err := store.Save(context.Background(), "webhook", state, loaded.Version); err != nil {
		t.Fatal(err)
	}
}

func TestDiscovererUsesCurrentSelectedNodeIPs(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "uid", Labels: map[string]string{"zeist.io/firecracker-capable": "true"}}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.9"}}}})
	discoverer := Discoverer{Client: client, Names: Names{NodeSelector: map[string]string{"zeist.io/firecracker-capable": "true"}}}
	targets, err := discoverer.Discover(context.Background(), rotation.Domain{Name: "mtls"})
	if err != nil || len(targets) != 1 || targets[0].Evidence["internalIP"] != "10.0.0.9" {
		t.Fatalf("targets = %#v, %v", targets, err)
	}
	if got := targets[0].Evidence["port"]; got != "10443" {
		t.Fatalf("default target port = %q, want 10443", got)
	}
}

func TestDiscovererIncludesEveryReadyWebhookManager(t *testing.T) {
	client := fake.NewSimpleClientset(
		readyAcknowledgementPod("ready-manager", "ready-uid", "", map[string]string{"app": "manager"}),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "not-ready-manager", Namespace: "system", UID: types.UID("not-ready-uid"), Labels: map[string]string{"app": "manager"}}},
	)
	discoverer := Discoverer{Client: client, Names: Names{Namespace: "system", WebhookService: "webhook", ManagerPodSelector: "app=manager"}}
	targets, err := discoverer.Discover(context.Background(), rotation.Domain{Name: "webhook"})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("Discover() targets = %#v, want API-server plus one Ready manager", targets)
	}
	if targets[0].ID != "apiserver:webhook" || targets[0].Evidence["probeOnly"] != "true" {
		t.Fatalf("Discover() probe target = %#v", targets[0])
	}
	if targets[1].ID != "manager:ready-uid" || targets[1].Evidence["role"] != "webhook" {
		t.Fatalf("Discover() manager target = %#v", targets[1])
	}
}

func TestPublisherPreservesOnlyCurrentGenerationData(t *testing.T) {
	path := "/validate"
	client := fake.NewSimpleClientset(
		&admissionv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "webhooks"}, Webhooks: []admissionv1.MutatingWebhook{{ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "service", Namespace: "system", Path: &path}}}}},
		&admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "webhooks"}, Webhooks: []admissionv1.ValidatingWebhook{{ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "service", Namespace: "system", Path: &path}}}}},
		&admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "canary-webhooks"}, Webhooks: []admissionv1.ValidatingWebhook{{ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "canary-service", Namespace: "system", Path: &path}}}}},
	)
	publisher := Publisher{
		Client: client,
		Names: Names{
			Namespace: "system", WebhookSecret: "webhook", WebhookService: "service",
			WebhookCanarySecret: "canary", WebhookCanaryService: "canary-service", WebhookCanaryConfiguration: "canary-webhooks",
			WebhookConfigurationNames: []string{"webhooks"},
		},
		Material: func(publication rotation.Publication) (PublicationMaterial, error) {
			return PublicationMaterial{
				WebhookTLS:        map[string][]byte{"tls.crt": []byte("cert"), "tls.key": []byte("key")},
				WebhookCanaryTLS:  map[string][]byte{"tls.crt": []byte("canary-cert"), "tls.key": []byte("canary-key")},
				TrustBundle:       []byte("trust"),
				CanaryTrustBundle: []byte("candidate-trust"),
			}, nil
		},
	}
	publication := rotation.Publication{Domain: "webhook", Generation: 7, OperationID: "operation", Materials: map[string]rotation.MaterialFingerprint{
		"webhook": {LeafFingerprint: "leaf", TrustFingerprint: "trust"},
		"canary":  {LeafFingerprint: "canary-leaf", TrustFingerprint: "candidate-trust"},
	}}
	if err := publisher.Publish(context.Background(), publication); err != nil {
		t.Fatal(err)
	}
	secret, err := client.CoreV1().Secrets("system").Get(context.Background(), "webhook", metav1.GetOptions{})
	if err != nil || string(secret.Data["tls.crt"]) != "cert" || secret.Annotations[annotationGeneration] != "7" {
		t.Fatalf("secret = %#v, %v", secret, err)
	}
	canary, err := client.CoreV1().Secrets("system").Get(context.Background(), "canary", metav1.GetOptions{})
	if err != nil || string(canary.Data["tls.crt"]) != "canary-cert" || canary.Annotations[annotationLeafFingerprint] != "canary-leaf" {
		t.Fatalf("canary Secret = %#v, %v", canary, err)
	}
	production, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.Background(), "webhooks", metav1.GetOptions{})
	if err != nil || string(production.Webhooks[0].ClientConfig.CABundle) != "trust" {
		t.Fatalf("production trust = %#v, %v", production, err)
	}
	productionValidating, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(context.Background(), "webhooks", metav1.GetOptions{})
	if err != nil || string(productionValidating.Webhooks[0].ClientConfig.CABundle) != "trust" {
		t.Fatalf("validating production trust = %#v, %v", productionValidating, err)
	}
	canaryConfiguration, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(context.Background(), "canary-webhooks", metav1.GetOptions{})
	if err != nil || string(canaryConfiguration.Webhooks[0].ClientConfig.CABundle) != "candidate-trust" {
		t.Fatalf("canary trust = %#v, %v", canaryConfiguration, err)
	}
	if !publicationOrderIsSafe(client.Actions()) {
		t.Fatalf("publication did not write canary, trust, then production: %#v", client.Actions())
	}
}

func publicationOrderIsSafe(actions []k8stesting.Action) bool {
	canaryCreate, firstTrustUpdate, productionCreate := -1, -1, -1
	for index, action := range actions {
		resource := action.GetResource().Resource
		if action.GetVerb() == "create" && resource == "secrets" {
			create, ok := action.(k8stesting.CreateAction)
			if !ok {
				return false
			}
			secret, ok := create.GetObject().(*corev1.Secret)
			if !ok {
				return false
			}
			switch secret.Name {
			case "canary":
				canaryCreate = index
			case "webhook":
				productionCreate = index
			}
		}
		if action.GetVerb() == "update" && (resource == "mutatingwebhookconfigurations" || resource == "validatingwebhookconfigurations") && firstTrustUpdate == -1 {
			firstTrustUpdate = index
		}
	}
	return canaryCreate >= 0 && firstTrustUpdate > canaryCreate && productionCreate > firstTrustUpdate
}

func TestPublisherPreservesUnmanagedAnnotationsOnIdempotentReplay(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "server", Namespace: "system", Annotations: map[string]string{"external.example/audit": "keep"}},
	})
	publisher := Publisher{Client: client, Names: Names{Namespace: "system", ServerSecret: "server"}}
	publication := rotation.Publication{
		Domain: "mtls", Generation: 7, OperationID: "operation",
		Materials: map[string]rotation.MaterialFingerprint{"server": {LeafFingerprint: "leaf", TrustFingerprint: "trust"}},
		Opaque:    &PublicationMaterial{ServerTLS: map[string][]byte{"tls.crt": []byte("cert"), "tls.key": []byte("key"), "ca.crt": []byte("trust")}},
	}
	data := publication.Opaque.(*PublicationMaterial).ServerTLS
	if err := publisher.applySecret(context.Background(), "server", corev1.SecretTypeTLS, data, publication, "server"); err != nil {
		t.Fatal(err)
	}
	if err := publisher.applySecret(context.Background(), "server", corev1.SecretTypeTLS, data, publication, "server"); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	secret, err := client.CoreV1().Secrets("system").Get(context.Background(), "server", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if secret.Annotations["external.example/audit"] != "keep" {
		t.Fatalf("unmanaged annotation lost: %#v", secret.Annotations)
	}
}

func TestPublisherRecoveryRefusesForeignCanarySecret(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "canary", Namespace: "system", Annotations: map[string]string{annotationDomain: "mtls"}},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": []byte("old-cert"), "tls.key": []byte("old-key")},
	})
	publisher := Publisher{Client: client, Names: Names{Namespace: "system"}}
	publication := rotation.Publication{
		Domain: "webhook", Generation: 2, OperationID: "recover", AdoptExisting: true,
		Materials: map[string]rotation.MaterialFingerprint{"canary": {LeafFingerprint: "leaf", TrustFingerprint: "trust"}},
	}
	if err := publisher.applySecret(context.Background(), "canary", corev1.SecretTypeTLS, map[string][]byte{"tls.crt": []byte("new-cert"), "tls.key": []byte("new-key")}, publication, "canary"); err == nil {
		t.Fatal("recovery overwrote a foreign managed canary Secret")
	}
}

func TestVerifierRejectsExpiredAcknowledgementLease(t *testing.T) {
	now := time.Now().UTC()
	payload, err := EncodeAcknowledgement(AcknowledgementLeaseData{Generation: 1, LeafFingerprint: "leaf", TrustFingerprint: "trust"})
	if err != nil {
		t.Fatal(err)
	}
	duration := int32(30)
	holder := "pod"
	expiredAt := metav1.NewMicroTime(now.Add(-31 * time.Second))
	client := fake.NewSimpleClientset(&coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: AcknowledgementLeaseName("mtls", "manager:pod"), Namespace: "acks", Annotations: map[string]string{acknowledgementAnnotation: payload}},
		Spec:       coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &duration, RenewTime: &expiredAt},
	})
	verifier := Verifier{Client: client, Names: Names{Namespace: "system", AcknowledgementNamespace: "acks"}}
	request := rotation.VerificationRequest{Domain: rotation.Domain{Name: "mtls"}, Generation: 1, Targets: []rotation.Target{{ID: "manager:pod", Evidence: map[string]string{"role": "client"}}}, Publication: rotation.Publication{Materials: map[string]rotation.MaterialFingerprint{"client": {LeafFingerprint: "leaf", TrustFingerprint: "trust"}}}}
	if _, err := verifier.Verify(context.Background(), request); err == nil {
		t.Fatal("Verifier accepted an expired acknowledgement Lease")
	}
}

func TestVerifierAcceptsAcknowledgementsFromExpectedReadyConsumers(t *testing.T) {
	managerTarget := rotation.Target{ID: "manager:manager-uid", Evidence: map[string]string{"role": "client"}}
	nodeTarget := rotation.Target{ID: "node:node-uid", Evidence: map[string]string{"role": "server", "nodeName": "node-a"}}
	request := acknowledgementVerificationRequest(managerTarget, nodeTarget)
	client := fake.NewSimpleClientset(
		acknowledgementLease(t, managerTarget.ID, "manager-uid", request.Publication.Materials["client"]),
		acknowledgementLease(t, nodeTarget.ID, "zeistd-uid", request.Publication.Materials["server"]),
		readyAcknowledgementPod("manager", "manager-uid", "", map[string]string{"app": "manager"}),
		readyAcknowledgementPod("zeistd", "zeistd-uid", "node-a", map[string]string{"app": "zeistd"}),
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-uid")}},
	)
	verifier := Verifier{Client: client, Names: acknowledgementNames()}
	acknowledgements, err := verifier.Verify(context.Background(), request)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(acknowledgements) != 2 {
		t.Fatalf("Verify() acknowledgements = %#v, want two", acknowledgements)
	}
}

func TestVerifierRejectsForgedManagerAcknowledgement(t *testing.T) {
	target := rotation.Target{ID: "manager:manager-uid", Evidence: map[string]string{"role": "client"}}
	request := acknowledgementVerificationRequest(target)
	client := fake.NewSimpleClientset(
		acknowledgementLease(t, target.ID, "other-manager-uid", request.Publication.Materials["client"]),
		readyAcknowledgementPod("manager", "manager-uid", "", map[string]string{"app": "manager"}),
		readyAcknowledgementPod("other-manager", "other-manager-uid", "", map[string]string{"app": "manager"}),
	)
	verifier := Verifier{Client: client, Names: acknowledgementNames()}
	if _, err := verifier.Verify(context.Background(), request); err == nil {
		t.Fatal("Verifier accepted acknowledgement held by a different Ready manager Pod")
	}
}

func TestVerifierAcceptsReadyManagerWebhookAcknowledgement(t *testing.T) {
	target := rotation.Target{ID: "manager:manager-uid", Evidence: map[string]string{"role": "webhook"}}
	material := rotation.MaterialFingerprint{LeafFingerprint: "webhook-leaf", TrustFingerprint: "webhook-trust"}
	request := rotation.VerificationRequest{
		Domain:     rotation.Domain{Name: "webhook"},
		Generation: 7,
		Targets:    []rotation.Target{target},
		Publication: rotation.Publication{Materials: map[string]rotation.MaterialFingerprint{
			"webhook": material,
		}},
	}
	client := fake.NewSimpleClientset(
		acknowledgementLeaseForDomain(t, "webhook", target.ID, "manager-uid", material),
		readyAcknowledgementPod("manager", "manager-uid", "", map[string]string{"app": "manager"}),
	)
	verifier := Verifier{Client: client, Names: acknowledgementNames()}
	acknowledgements, err := verifier.Verify(context.Background(), request)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(acknowledgements) != 1 || acknowledgements[0].LeafFingerprint != material.LeafFingerprint {
		t.Fatalf("Verify() acknowledgements = %#v", acknowledgements)
	}
}

func TestVerifierRejectsForgedNodeAcknowledgement(t *testing.T) {
	target := rotation.Target{ID: "node:node-uid", Evidence: map[string]string{"role": "server", "nodeName": "node-a"}}
	request := acknowledgementVerificationRequest(target)
	client := fake.NewSimpleClientset(
		acknowledgementLease(t, target.ID, "zeistd-other-uid", request.Publication.Materials["server"]),
		readyAcknowledgementPod("zeistd-other", "zeistd-other-uid", "node-b", map[string]string{"app": "zeistd"}),
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-uid")}},
	)
	verifier := Verifier{Client: client, Names: acknowledgementNames()}
	if _, err := verifier.Verify(context.Background(), request); err == nil {
		t.Fatal("Verifier accepted acknowledgement held by zeistd on a different Node")
	}
}

func TestVerifierRejectsAcknowledgementForReplacedNode(t *testing.T) {
	target := rotation.Target{ID: "node:old-node-uid", Evidence: map[string]string{"role": "server", "nodeName": "node-a"}}
	request := acknowledgementVerificationRequest(target)
	client := fake.NewSimpleClientset(
		acknowledgementLease(t, target.ID, "zeistd-uid", request.Publication.Materials["server"]),
		readyAcknowledgementPod("zeistd", "zeistd-uid", "node-a", map[string]string{"app": "zeistd"}),
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("new-node-uid")}},
	)
	verifier := Verifier{Client: client, Names: acknowledgementNames()}
	if _, err := verifier.Verify(context.Background(), request); err == nil {
		t.Fatal("Verifier accepted acknowledgement for a replacement Node")
	}
}

func acknowledgementNames() Names {
	return Names{
		Namespace:                "system",
		AcknowledgementNamespace: "acks",
		ManagerPodSelector:       "app=manager",
		ZeistdPodSelector:        "app=zeistd",
	}
}

func acknowledgementVerificationRequest(targets ...rotation.Target) rotation.VerificationRequest {
	return rotation.VerificationRequest{
		Domain:     rotation.Domain{Name: "mtls"},
		Generation: 7,
		Targets:    targets,
		Publication: rotation.Publication{Materials: map[string]rotation.MaterialFingerprint{
			"client": {LeafFingerprint: "client-leaf", TrustFingerprint: "client-trust"},
			"server": {LeafFingerprint: "server-leaf", TrustFingerprint: "server-trust"},
		}},
	}
}

func acknowledgementLease(t *testing.T, targetID, holderIdentity string, material rotation.MaterialFingerprint) *coordinationv1.Lease {
	return acknowledgementLeaseForDomain(t, "mtls", targetID, holderIdentity, material)
}

func acknowledgementLeaseForDomain(t *testing.T, domain, targetID, holderIdentity string, material rotation.MaterialFingerprint) *coordinationv1.Lease {
	t.Helper()
	payload, err := EncodeAcknowledgement(AcknowledgementLeaseData{
		Generation:       7,
		LeafFingerprint:  material.LeafFingerprint,
		TrustFingerprint: material.TrustFingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	duration := int32(30)
	renewedAt := metav1.NewMicroTime(time.Now().UTC())
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:        AcknowledgementLeaseName(domain, targetID),
			Namespace:   "acks",
			Annotations: map[string]string{acknowledgementAnnotation: payload},
		},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       &holderIdentity,
			LeaseDurationSeconds: &duration,
			RenewTime:            &renewedAt,
		},
	}
}

func readyAcknowledgementPod(name, uid, nodeName string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "system", UID: types.UID(uid), Labels: labels},
		Spec:       corev1.PodSpec{NodeName: nodeName},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{
				Type: corev1.PodReady, Status: corev1.ConditionTrue,
			}},
		},
	}
}

func TestAcknowledgementLeaseDataUsesNumericGeneration(t *testing.T) {
	data, err := EncodeAcknowledgement(AcknowledgementLeaseData{Generation: 42, LeafFingerprint: "leaf", TrustFingerprint: "trust"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(data), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["generation"] != float64(42) {
		t.Fatalf("generation JSON type/value = %#v, want numeric 42", decoded["generation"])
	}
}
