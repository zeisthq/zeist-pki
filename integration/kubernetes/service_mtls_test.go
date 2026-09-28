package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/zeisthq/zeist-pki/pki"
	"github.com/zeisthq/zeist-pki/rotation"
)

func TestServiceMTLSIssuancePublicationDiscoveryAndProbe(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	configured := ServiceMTLSNames{
		ServerNamespace: "servers", ServerService: "api", ServerSecret: "api-server-tls", ServerPodSelector: "role=server", ServerPort: 443,
		ClientNamespace: "clients", ClientSecret: "api-client-tls", ClientPodSelector: "role=client", ClusterDomain: "cluster.local",
	}
	serverPod := readyServicePod("servers", "server", "server-uid", map[string]string{"role": "server"})
	serverPod.Spec.HostNetwork = true
	serverPod.Status.PodIP = "10.0.0.7"
	clientPod := readyServicePod("clients", "client", "client-uid", map[string]string{"role": "client"})
	cluster := fake.NewSimpleClientset(serverPod, clientPod)
	names := Names{Namespace: "issuer", AcknowledgementNamespace: "acks", ServiceMTLS: map[string]ServiceMTLSNames{"api-access": configured}}
	domain := rotation.Domain{
		Name: "api-access", Profile: rotation.ProfileServiceMTLS, ConfigurationHash: "sha256:config", Policy: rotation.DefaultPolicy(),
		Metadata: map[string]string{"bindingHash": "sha256:binding"},
	}
	targets, err := (Discoverer{Client: cluster, Names: names}).Discover(ctx, domain)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 {
		t.Fatalf("targets = %#v, want probe and two Ready Pods", targets)
	}

	issuer := Issuer{Client: cluster, Names: names, Now: func() time.Time { return now }}
	root, err := issuer.CreateRoot(ctx, domain)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := issuer.Issue(ctx, rotation.IssueRequest{
		Domain: domain, Signer: root, TrustRoots: []rotation.Root{root}, Targets: targets, Generation: 7, OperationID: "operation",
	})
	if err != nil {
		t.Fatal(err)
	}
	publication.Domain = domain.Name
	publication.Generation = 7
	publication.OperationID = "operation"
	if err := (Publisher{Client: cluster, Names: names}).Publish(ctx, publication); err != nil {
		t.Fatal(err)
	}
	serverSecret, err := cluster.CoreV1().Secrets(configured.ServerNamespace).Get(ctx, configured.ServerSecret, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	clientSecret, err := cluster.CoreV1().Secrets(configured.ClientNamespace).Get(ctx, configured.ClientSecret, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(serverSecret.Data) != 3 || len(clientSecret.Data) != 3 {
		t.Fatalf("published Secret keys = server:%v client:%v", keys(serverSecret.Data), keys(clientSecret.Data))
	}
	serverLeaf, err := pki.ParseLeafPEM(serverSecret.Data["tls.crt"], serverSecret.Data["tls.key"])
	if err != nil {
		t.Fatal(err)
	}
	for _, hostname := range []string{"api.servers.svc", "api.servers.svc.cluster.local"} {
		if err := serverLeaf.Certificate.VerifyHostname(hostname); err != nil {
			t.Fatalf("server leaf does not identify %s: %v", hostname, err)
		}
	}
	recovered, generation, leafNotAfter, err := (Recoverer{Client: cluster, Names: names, Now: func() time.Time { return now }}).survivingDomain(ctx, domain, root.Fingerprint)
	if err != nil {
		t.Fatalf("recover service mTLS outputs: %v", err)
	}
	if recovered.Fingerprint != root.Fingerprint || generation != 7 || leafNotAfter.IsZero() {
		t.Fatalf("recovered root=%#v generation=%d leafNotAfter=%v", recovered, generation, leafNotAfter)
	}

	dial, result := startMTLSPipe(t, serverSecret)
	request := rotation.VerificationRequest{Domain: domain, Generation: 7, Targets: targets, Publication: publication}
	if err := probeServiceMTLSWithDial(ctx, cluster, configured, request, dial); err != nil {
		t.Fatalf("probe service mTLS: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	for _, target := range targets {
		if target.Evidence["probeOnly"] == "true" {
			continue
		}
		material, found := publication.MaterialFor(target)
		if !found {
			t.Fatalf("target %q has no publication material", target.ID)
		}
		lease := acknowledgementLeaseForDomain(t, domain.Name, target.ID, target.Evidence["podUID"], material)
		if _, err := cluster.CoordinationV1().Leases("acks").Create(ctx, lease, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	verifier := Verifier{Client: cluster, Names: names, Probe: func(context.Context, rotation.VerificationRequest) error { return nil }}
	acknowledgements, err := verifier.Verify(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(acknowledgements) != len(targets) {
		t.Fatalf("acknowledgements = %#v, want one per target", acknowledgements)
	}

	configured.ServerProbeOnly = true
	names.ServiceMTLS[domain.Name] = configured
	secondServer := readyServicePod("servers", "server-two", "server-two-uid", map[string]string{"role": "server"})
	secondServer.Spec.HostNetwork = true
	secondServer.Status.PodIP = "10.0.0.8"
	if _, err := cluster.CoreV1().Pods("servers").Create(ctx, secondServer, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	probeTargets, err := (Discoverer{Client: cluster, Names: names}).Discover(ctx, domain)
	if err != nil {
		t.Fatal(err)
	}
	if len(probeTargets) != 4 || probeTargets[2].Evidence["probeOnly"] != "true" ||
		probeTargets[2].Evidence["podIP"] != secondServer.Status.PodIP ||
		probeTargets[3].Evidence["podIP"] != serverPod.Status.PodIP {
		t.Fatalf("direct-probe targets = %#v", probeTargets)
	}
	if err := cluster.CoordinationV1().Leases("acks").Delete(ctx,
		AcknowledgementLeaseName(domain.Name, "server:server-uid"), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	serviceDial, serviceResult := startMTLSPipe(t, serverSecret)
	secondPodDial, secondPodResult := startMTLSPipe(t, serverSecret)
	firstPodDial, firstPodResult := startMTLSPipe(t, serverSecret)
	seen := make([]string, 0, 3)
	probeRequest := rotation.VerificationRequest{Domain: domain, Generation: 7, Targets: probeTargets, Publication: publication}
	if err := probeServiceMTLSWithAddressDial(ctx, cluster, names, probeRequest,
		func(ctx context.Context, config *tls.Config, address string) (*tls.Conn, error) {
			seen = append(seen, address)
			switch len(seen) {
			case 1:
				return serviceDial(ctx, config)
			case 2:
				return secondPodDial(ctx, config)
			case 3:
				return firstPodDial(ctx, config)
			default:
				return nil, errors.New("unexpected extra probe")
			}
		}); err != nil {
		t.Fatalf("probe every Ready server: %v", err)
	}
	if len(seen) != 3 || seen[0] != "api.servers.svc:443" ||
		seen[1] != "10.0.0.8:443" || seen[2] != "10.0.0.7:443" {
		t.Fatalf("probe addresses = %#v", seen)
	}
	for _, result := range []<-chan error{serviceResult, secondPodResult, firstPodResult} {
		if err := <-result; err != nil {
			t.Fatalf("direct-probe handshake: %v", err)
		}
	}
	freshServiceDial, freshServiceResult := startMTLSPipe(t, serverSecret)
	if err := probeServiceMTLSWithAddressDial(ctx, cluster, names, probeRequest,
		func(ctx context.Context, config *tls.Config, address string) (*tls.Conn, error) {
			if address == "10.0.0.8:443" {
				return nil, errors.New("stale broker identity")
			}
			return freshServiceDial(ctx, config)
		}); err == nil {
		t.Fatal("accepted one Ready broker that failed direct TLS verification")
	}
	if err := <-freshServiceResult; err != nil {
		t.Fatal(err)
	}
	verifier.Probe = func(context.Context, rotation.VerificationRequest) error { return nil }
	if _, err := verifier.Verify(ctx, probeRequest); err != nil {
		t.Fatalf("probe-only server needed a Lease: %v", err)
	}
}

func TestServiceMTLSPublicationReplaysAfterPartialWrite(t *testing.T) {
	configured := ServiceMTLSNames{ServerNamespace: "servers", ServerSecret: "server", ClientNamespace: "clients", ClientSecret: "client"}
	cluster := fake.NewSimpleClientset()
	failed := false
	cluster.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		create := action.(k8stesting.CreateAction)
		secret := create.GetObject().(*corev1.Secret)
		if secret.Namespace == configured.ClientNamespace && secret.Name == configured.ClientSecret && !failed {
			failed = true
			return true, nil, errors.New("injected client publication failure")
		}
		return false, nil, nil
	})
	names := Names{ServiceMTLS: map[string]ServiceMTLSNames{"service": configured}}
	publication := rotation.Publication{
		Domain: "service", Generation: 3, OperationID: "operation",
		Materials: map[string]rotation.MaterialFingerprint{
			"server": {LeafFingerprint: "sha256:server", TrustFingerprint: "sha256:trust"},
			"client": {LeafFingerprint: "sha256:client", TrustFingerprint: "sha256:trust"},
		},
		Opaque: &PublicationMaterial{
			ServerTLS: map[string][]byte{"tls.crt": []byte("server-cert"), "tls.key": []byte("server-key"), "ca.crt": []byte("trust")},
			ClientTLS: map[string][]byte{"tls.crt": []byte("client-cert"), "tls.key": []byte("client-key"), "ca.crt": []byte("trust")},
		},
	}
	publisher := Publisher{Client: cluster, Names: names}
	if err := publisher.Publish(context.Background(), publication); err == nil {
		t.Fatal("partial publication unexpectedly succeeded")
	}
	if err := publisher.Publish(context.Background(), publication); err != nil {
		t.Fatalf("replayed publication: %v", err)
	}
	if _, err := cluster.CoreV1().Secrets(configured.ServerNamespace).Get(context.Background(), configured.ServerSecret, metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.CoreV1().Secrets(configured.ClientNamespace).Get(context.Background(), configured.ClientSecret, metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
}

func readyServicePod(namespace, name, uid string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uid), Labels: labels},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
}

func startMTLSPipe(t *testing.T, secret *corev1.Secret) (func(context.Context, *tls.Config) (*tls.Conn, error), <-chan error) {
	t.Helper()
	certificate, err := tls.X509KeyPair(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil {
		t.Fatal(err)
	}
	roots, err := pki.ParseCertificatesPEM(secret.Data["ca.crt"])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	for _, root := range roots {
		pool.AddCert(root)
	}
	serverConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
	}
	serverSide, clientSide := net.Pipe()
	server := tls.Server(serverSide, serverConfig)
	result := make(chan error, 1)
	go func() {
		err := server.Handshake()
		_ = server.Close()
		result <- err
	}()
	return func(ctx context.Context, config *tls.Config) (*tls.Conn, error) {
		client := tls.Client(clientSide, config)
		if err := client.HandshakeContext(ctx); err != nil {
			_ = client.Close()
			return nil, err
		}
		return client, nil
	}, result
}

func keys(data map[string][]byte) []string {
	result := make([]string, 0, len(data))
	for key := range data {
		result = append(result, key)
	}
	return result
}
