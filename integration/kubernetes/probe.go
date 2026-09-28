package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"

	"github.com/zeisthq/zeist-pki/pki"
	"github.com/zeisthq/zeist-pki/rotation"
)

// LiveProbe returns the bundled Zeist activation probe. It verifies each
// mTLS node with TLS 1.3 /v2/status using the just-published client identity.
// For webhook trust it verifies the exact configured caBundle, a dry-run
// admission canary, and a TLS handshake to the configured Service.
// WebhookCanary proves that Kubernetes API-server admission traversed the
// configured webhook trust relationship. Implementations must return an error
// for every endpoint that does not complete the dry-run request.
type WebhookCanary func(context.Context) error

func LiveProbe(client kubernetes.Interface, names Names, canary ...WebhookCanary) func(context.Context, rotation.VerificationRequest) error {
	webhookCanary := defaultWebhookCanary(client, names)
	if len(canary) > 1 {
		return func(context.Context, rotation.VerificationRequest) error {
			return fmt.Errorf("only one webhook admission canary is supported")
		}
	}
	if len(canary) == 1 && canary[0] != nil {
		webhookCanary = canary[0]
	}
	return func(ctx context.Context, request rotation.VerificationRequest) error {
		switch request.Domain.Profile {
		case rotation.ProfileMTLS:
			return probeMTLS(ctx, client, names, request)
		case rotation.ProfileWebhook:
			return probeWebhook(ctx, client, names, request, webhookCanary)
		case rotation.ProfileServiceMTLS:
			return probeServiceMTLS(ctx, client, names, request)
		default:
			return fmt.Errorf("unsupported probe domain profile %q", request.Domain.Profile)
		}
	}
}

func probeServiceMTLS(ctx context.Context, client kubernetes.Interface, names Names, request rotation.VerificationRequest) error {
	return probeServiceMTLSWithAddressDial(ctx, client, names, request, func(ctx context.Context, tlsConfig *tls.Config, address string) (*tls.Conn, error) {
		dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: tlsConfig}
		connection, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		tlsConnection, ok := connection.(*tls.Conn)
		if !ok {
			_ = connection.Close()
			return nil, fmt.Errorf("service TLS dial returned a non-TLS connection")
		}
		return tlsConnection, nil
	})
}

func probeServiceMTLSWithAddressDial(ctx context.Context, client kubernetes.Interface, names Names,
	request rotation.VerificationRequest, dial func(context.Context, *tls.Config, string) (*tls.Conn, error)) error {
	configured, err := names.serviceMTLS(request.Domain.Name)
	if err != nil {
		return err
	}
	tlsConfig, err := serviceProbeTLSConfig(ctx, client, configured, request)
	if err != nil {
		return err
	}
	serverName, _ := serviceDNSNames(configured)
	address := net.JoinHostPort(serverName, strconv.Itoa(int(configured.ServerPort)))
	probe := func(address string) error {
		return probeServiceTLSWithDial(ctx, tlsConfig, func(ctx context.Context, tlsConfig *tls.Config) (*tls.Conn, error) {
			return dial(ctx, tlsConfig, address)
		})
	}
	if err := probe(address); err != nil {
		return err
	}
	if !configured.ServerProbeOnly {
		return nil
	}
	servicePort, err := serviceProbePort(ctx, client, configured)
	if err != nil {
		return err
	}
	for _, target := range request.Targets {
		if target.Evidence["role"] != "server" || target.Evidence["podUID"] == "" {
			continue
		}
		if target.Evidence["probeOnly"] != "true" {
			return fmt.Errorf("server target %s lacks required direct-probe evidence", target.ID)
		}
		podIP := target.Evidence["podIP"]
		if net.ParseIP(podIP) == nil {
			return fmt.Errorf("probe-only target %s has invalid Pod IP", target.ID)
		}
		port, err := servicePodProbePort(ctx, client, configured, servicePort, target)
		if err != nil {
			return fmt.Errorf("probe server %s: %w", target.ID, err)
		}
		address := net.JoinHostPort(podIP, strconv.Itoa(int(port)))
		if err := probe(address); err != nil {
			return fmt.Errorf("probe server %s: %w", target.ID, err)
		}
	}
	return nil
}

func probeServiceMTLSWithDial(ctx context.Context, client kubernetes.Interface, configured ServiceMTLSNames, request rotation.VerificationRequest, dial func(context.Context, *tls.Config) (*tls.Conn, error)) error {
	tlsConfig, err := serviceProbeTLSConfig(ctx, client, configured, request)
	if err != nil {
		return err
	}
	return probeServiceTLSWithDial(ctx, tlsConfig, dial)
}

func serviceProbeTLSConfig(ctx context.Context, client kubernetes.Interface, configured ServiceMTLSNames, request rotation.VerificationRequest) (*tls.Config, error) {
	readContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	secret, err := client.CoreV1().Secrets(configured.ClientNamespace).Get(readContext, configured.ClientSecret, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("read published service client Secret: %w", err)
	}
	expectedClient, found := request.Publication.Materials["client"]
	if !found {
		return nil, fmt.Errorf("service-mTLS publication has no client material")
	}
	expectedServer, found := request.Publication.Materials["server"]
	if !found {
		return nil, fmt.Errorf("service-mTLS publication has no server material")
	}
	clientLeaf, err := pki.ParseLeafPEM(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil {
		return nil, fmt.Errorf("parse published service client Secret: %w", err)
	}
	if certificateFingerprint(clientLeaf.Certificate) != expectedClient.LeafFingerprint {
		return nil, fmt.Errorf("published service client leaf fingerprint does not match verification request")
	}
	roots, err := pki.ParseCertificatesPEM(secret.Data["ca.crt"])
	if err != nil {
		return nil, fmt.Errorf("parse published service trust bundle: %w", err)
	}
	if bundleFingerprint(roots) != expectedClient.TrustFingerprint || expectedServer.TrustFingerprint != expectedClient.TrustFingerprint {
		return nil, fmt.Errorf("published service trust fingerprint does not match verification request")
	}
	tlsCertificate, err := tls.X509KeyPair(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil {
		return nil, fmt.Errorf("load published service client key pair: %w", err)
	}
	pool := x509.NewCertPool()
	for _, root := range roots {
		pool.AddCert(root)
	}
	serverName, _ := serviceDNSNames(configured)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   serverName,
		RootCAs:      pool,
		Certificates: []tls.Certificate{tlsCertificate},
		VerifyPeerCertificate: func(rawCertificates [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeerFingerprint(rawCertificates, expectedServer.LeafFingerprint, "service")
		},
	}, nil
}

func probeServiceTLSWithDial(ctx context.Context, tlsConfig *tls.Config, dial func(context.Context, *tls.Config) (*tls.Conn, error)) error {
	connection, err := dial(ctx, tlsConfig)
	if err != nil {
		return fmt.Errorf("probe service mTLS: %w", err)
	}
	defer connection.Close()
	if connection.ConnectionState().Version != tls.VersionTLS13 {
		return fmt.Errorf("probe service mTLS did not negotiate TLS 1.3")
	}
	return nil
}

func serviceProbePort(ctx context.Context, client kubernetes.Interface, configured ServiceMTLSNames) (corev1.ServicePort, error) {
	readContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	service, err := client.CoreV1().Services(configured.ServerNamespace).Get(readContext, configured.ServerService, metav1.GetOptions{})
	if err != nil {
		return corev1.ServicePort{}, fmt.Errorf("read probed service: %w", err)
	}
	var selected *corev1.ServicePort
	for index := range service.Spec.Ports {
		port := &service.Spec.Ports[index]
		if port.Port != configured.ServerPort || (port.Protocol != "" && port.Protocol != corev1.ProtocolTCP) {
			continue
		}
		if selected != nil {
			return corev1.ServicePort{}, fmt.Errorf("service has ambiguous TCP port %d", configured.ServerPort)
		}
		selected = port
	}
	if selected == nil {
		return corev1.ServicePort{}, fmt.Errorf("service has no TCP port %d", configured.ServerPort)
	}
	return *selected, nil
}

func servicePodProbePort(ctx context.Context, client kubernetes.Interface, configured ServiceMTLSNames,
	servicePort corev1.ServicePort, target rotation.Target) (int32, error) {
	if servicePort.TargetPort.Type != intstr.String {
		port := servicePort.TargetPort.IntVal
		if port == 0 {
			port = servicePort.Port
		}
		if port <= 0 || port > 65535 {
			return 0, fmt.Errorf("service target port %d is invalid", port)
		}
		return port, nil
	}
	name := servicePort.TargetPort.StrVal
	if name == "" || target.Evidence["podNamespace"] != configured.ServerNamespace || target.Evidence["podName"] == "" {
		return 0, fmt.Errorf("named service target port has no exact Pod identity")
	}
	readContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pod, err := client.CoreV1().Pods(configured.ServerNamespace).Get(readContext, target.Evidence["podName"], metav1.GetOptions{})
	if err != nil {
		return 0, fmt.Errorf("read probed server Pod: %w", err)
	}
	if string(pod.UID) != target.Evidence["podUID"] || pod.Status.PodIP != target.Evidence["podIP"] {
		return 0, fmt.Errorf("probed server Pod identity changed")
	}
	var port int32
	for _, container := range pod.Spec.Containers {
		for _, candidate := range container.Ports {
			if candidate.Name != name || (candidate.Protocol != "" && candidate.Protocol != corev1.ProtocolTCP) {
				continue
			}
			if port != 0 {
				return 0, fmt.Errorf("Pod has ambiguous target port %q", name)
			}
			port = candidate.ContainerPort
		}
	}
	if port <= 0 || port > 65535 {
		return 0, fmt.Errorf("Pod has no valid TCP target port %q", name)
	}
	return port, nil
}

func probeMTLS(ctx context.Context, client kubernetes.Interface, names Names, request rotation.VerificationRequest) error {
	secret, err := client.CoreV1().Secrets(names.Namespace).Get(ctx, names.ClientSecret, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read published client Secret: %w", err)
	}
	expected, found := request.Publication.Materials["client"]
	if !found {
		return fmt.Errorf("mTLS publication has no client material")
	}
	certificate, err := pki.ParseLeafPEM(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil {
		return fmt.Errorf("parse published client Secret: %w", err)
	}
	if certificateFingerprint(certificate.Certificate) != expected.LeafFingerprint {
		return fmt.Errorf("published client leaf fingerprint does not match verification request")
	}
	roots, err := pki.ParseCertificatesPEM(secret.Data["ca.crt"])
	if err != nil {
		return fmt.Errorf("parse published mTLS trust bundle: %w", err)
	}
	if bundleFingerprint(roots) != expected.TrustFingerprint {
		return fmt.Errorf("published client trust fingerprint does not match verification request")
	}
	tlsCertificate, err := tls.X509KeyPair(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil {
		return fmt.Errorf("load published client key pair: %w", err)
	}
	pool := x509.NewCertPool()
	for _, root := range roots {
		pool.AddCert(root)
	}
	port := names.Port
	if port == 0 {
		port = 10443
	}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{tlsCertificate}, NextProtos: []string{"http/1.1"}}}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	for _, target := range request.Targets {
		if target.Evidence["role"] != "server" {
			continue
		}
		nodeUID, found := strings.CutPrefix(target.ID, "node:")
		if !found || nodeUID == "" {
			return fmt.Errorf("server probe target has invalid node identity %q", target.ID)
		}
		endpoint, err := nodeStatusEndpoint(target.Evidence["internalIP"], target.Evidence["port"], port)
		if err != nil {
			return fmt.Errorf("probe %s: %w", target.ID, err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-Zeist-Node-Name", target.Evidence["nodeName"])
		req.Header.Set("X-Zeist-Node-Uid", nodeUID)
		response, err := httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("probe %s: %w", target.ID, err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("probe %s: /v2/status returned HTTP %d", target.ID, response.StatusCode)
		}
	}
	return nil
}

// nodeStatusEndpoint renders a discovered InternalIP safely for a URL. In
// particular, IPv6 literals require brackets around the host portion; using
// string concatenation would make an otherwise valid node target unprobeable.
func nodeStatusEndpoint(internalIP, evidencePort string, defaultPort int32) (string, error) {
	if net.ParseIP(internalIP) == nil {
		return "", fmt.Errorf("server probe target has invalid InternalIP %q", internalIP)
	}
	port := evidencePort
	if port == "" {
		port = strconv.Itoa(int(defaultPort))
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsed == 0 {
		return "", fmt.Errorf("server probe target has invalid port %q", port)
	}
	return "https://" + net.JoinHostPort(internalIP, port) + "/v2/status", nil
}

func probeWebhook(ctx context.Context, client kubernetes.Interface, names Names, request rotation.VerificationRequest, canary WebhookCanary) error {
	expected, found := request.Publication.Materials["webhook"]
	if !found {
		return fmt.Errorf("webhook publication has no material")
	}
	expectedCanary, found := request.Publication.Materials["canary"]
	if !found {
		return fmt.Errorf("webhook publication has no candidate canary material")
	}
	roots, err := (Recoverer{Client: client, Names: names}).webhookRoots(ctx)
	if err != nil {
		return err
	}
	if bundleFingerprint(roots) != expected.TrustFingerprint {
		return fmt.Errorf("configured webhook trust fingerprint does not match verification request")
	}
	canaryRoots, err := (Recoverer{Client: client, Names: names}).webhookCanaryRoots(ctx, roots)
	if err != nil {
		return err
	}
	if bundleFingerprint(canaryRoots) != expectedCanary.TrustFingerprint {
		return fmt.Errorf("configured webhook canary trust fingerprint does not match verification request")
	}
	if err := verifyPublishedWebhookSecret(ctx, client, names.Namespace, names.WebhookCanarySecret, names.WebhookCanaryService, canaryRoots, expectedCanary); err != nil {
		return fmt.Errorf("verify candidate webhook material: %w", err)
	}
	if canary == nil {
		return fmt.Errorf("webhook activation canary is required")
	}
	if err := canary(ctx); err != nil {
		return err
	}
	return probeWebhookServiceTLS(ctx, names, roots, expected)
}

func verifyPublishedWebhookSecret(ctx context.Context, client kubernetes.Interface, namespace, name, service string, roots []*x509.Certificate, expected rotation.MaterialFingerprint) error {
	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read Secret %s: %w", name, err)
	}
	leaf, err := pki.ParseLeafPEM(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil {
		return fmt.Errorf("parse Secret %s: %w", name, err)
	}
	if certificateFingerprint(leaf.Certificate) != expected.LeafFingerprint {
		return fmt.Errorf("Secret %s leaf fingerprint does not match verification request", name)
	}
	if secret.Annotations[annotationLeafFingerprint] != expected.LeafFingerprint || secret.Annotations[annotationTrustFingerprint] != expected.TrustFingerprint {
		return fmt.Errorf("Secret %s published fingerprint annotations do not match verification request", name)
	}
	if err := pki.ValidateLeaf(leaf, roots, pki.ProfileWebhook, time.Now().UTC()); err != nil {
		return fmt.Errorf("validate Secret %s: %w", name, err)
	}
	if err := validateWebhookServiceCertificate(leaf.Certificate, namespace, service); err != nil {
		return fmt.Errorf("validate Secret %s identity: %w", name, err)
	}
	return nil
}

// probeWebhookAdmissionCanary makes a narrowly selected dry-run admission
// request through the Kubernetes API server. It proves that the API server has
// accepted the currently published webhook trust bundle; direct Service TLS
// alone cannot prove that the API server's webhook client has reloaded it.
// Multiple configured API-server endpoints can be supplied through a
// client-go transport wrapper; this request must succeed through each such
// endpoint before the caller advances the rotation.
func defaultWebhookCanary(client kubernetes.Interface, names Names) WebhookCanary {
	return func(ctx context.Context) error {
		if client == nil || client.Discovery() == nil || client.Discovery().RESTClient() == nil {
			return fmt.Errorf("Kubernetes discovery REST client is required for webhook activation canary")
		}
		return submitWebhookAdmissionCanary(ctx, client.Discovery().RESTClient(), names.WebhookCanaryResourcePath, names.WebhookCanaryAnnotation)
	}
}

// NewWebhookAdmissionCanary constructs an API-server activation probe using
// the same authentication and TLS settings as the selected Kubernetes client.
// Supplying multiple endpoint origins is required for HA control planes whose
// individual API servers must each prove that they reloaded webhook trust.
func NewWebhookAdmissionCanary(config *rest.Config, endpoints []string, resourcePath, annotation string) (WebhookCanary, error) {
	if config == nil {
		return nil, fmt.Errorf("Kubernetes REST configuration is required")
	}
	if len(endpoints) == 0 {
		endpoints = []string{config.Host}
	}
	if resourcePath == "" || annotation == "" {
		return nil, fmt.Errorf("webhook canary resource path and annotation are required")
	}
	canonical := make([]string, 0, len(endpoints))
	seen := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		parsed, err := url.ParseRequestURI(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.RawPath != "" {
			return nil, fmt.Errorf("invalid API-server endpoint %q", endpoint)
		}
		origin := parsed.Scheme + "://" + parsed.Host
		if _, exists := seen[origin]; exists {
			continue
		}
		seen[origin] = struct{}{}
		canonical = append(canonical, origin)
	}
	sort.Strings(canonical)
	clients := make([]rest.Interface, 0, len(canonical))
	for _, endpoint := range canonical {
		endpointConfig := rest.CopyConfig(config)
		endpointConfig.Host = endpoint
		endpointConfig.APIPath = "/"
		endpointConfig.GroupVersion = nil
		endpointConfig.NegotiatedSerializer = clientgoscheme.Codecs.WithoutConversion()
		client, err := rest.UnversionedRESTClientFor(endpointConfig)
		if err != nil {
			return nil, fmt.Errorf("configure API-server endpoint %q: %w", endpoint, err)
		}
		clients = append(clients, client)
	}
	return func(ctx context.Context) error {
		for _, client := range clients {
			if err := submitWebhookAdmissionCanary(ctx, client, resourcePath, annotation); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

func submitWebhookAdmissionCanary(ctx context.Context, restClient rest.Interface, resourcePath, annotation string) error {
	if resourcePath == "" || annotation == "" {
		return fmt.Errorf("webhook canary resource path and annotation are required")
	}
	name := resourcePath[strings.LastIndex(resourcePath, "/")+1:]
	if name == "" {
		return fmt.Errorf("webhook canary resource path has no object name")
	}
	raw, err := restClient.Get().AbsPath(resourcePath).Do(ctx).Raw()
	if err != nil {
		return fmt.Errorf("read webhook rotation canary resource: %w", err)
	}
	var pool map[string]any
	if err := json.Unmarshal(raw, &pool); err != nil {
		return fmt.Errorf("decode webhook rotation canary resource: %w", err)
	}
	metadata, ok := pool["metadata"].(map[string]any)
	if !ok || metadata["name"] != name {
		return fmt.Errorf("webhook rotation canary response does not match %q", name)
	}
	if resourceVersion, _ := metadata["resourceVersion"].(string); resourceVersion == "" {
		return fmt.Errorf("webhook rotation canary resource has no resourceVersion")
	}
	annotations, _ := metadata["annotations"].(map[string]any)
	if annotations == nil {
		annotations = make(map[string]any)
		metadata["annotations"] = annotations
	}
	annotations[annotation] = time.Now().UTC().Format(time.RFC3339Nano)
	// Preserve controller-owned status exactly as it was returned. The canary
	// webhook rejects status changes, and retaining the fetched value makes the
	// dry-run valid even after the regular SandboxPool controller has populated
	// it. The probe mutates only its dedicated annotation.
	encoded, err := json.Marshal(pool)
	if err != nil {
		return fmt.Errorf("encode webhook rotation canary: %w", err)
	}
	result := restClient.Put().AbsPath(resourcePath).
		Param("dryRun", "All").SetHeader("Content-Type", "application/json").Body(encoded).Do(ctx)
	if err := result.Error(); err != nil {
		return fmt.Errorf("dry-run webhook rotation canary: %w", err)
	}
	return nil
}

func probeWebhookServiceTLS(ctx context.Context, names Names, roots []*x509.Certificate, expected rotation.MaterialFingerprint) error {
	pool := x509.NewCertPool()
	for _, root := range roots {
		pool.AddCert(root)
	}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pool, NextProtos: []string{"http/1.1"},
		VerifyPeerCertificate: func(rawCertificates [][]byte, _ [][]*x509.Certificate) error {
			return verifyWebhookPeerFingerprint(rawCertificates, expected.LeafFingerprint)
		},
	}}
	defer transport.CloseIdleConnections()
	service := names.WebhookService + "." + names.Namespace + ".svc"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+service+":443/healthz", nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("probe webhook Service TLS: %w", err)
	}
	_ = response.Body.Close()
	if response.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("probe webhook Service: HTTP %d", response.StatusCode)
	}
	return nil
}

// verifyWebhookPeerFingerprint is deliberately independent of transport I/O so
// the production activation invariant is testable without a listener. Standard
// TLS chain and hostname verification still run before this callback because
// InsecureSkipVerify remains false; this adds the exact published leaf check.
func verifyWebhookPeerFingerprint(rawCertificates [][]byte, expected string) error {
	return verifyPeerFingerprint(rawCertificates, expected, "webhook")
}

func verifyPeerFingerprint(rawCertificates [][]byte, expected, peer string) error {
	if expected == "" {
		return fmt.Errorf("expected %s leaf fingerprint is required", peer)
	}
	if len(rawCertificates) == 0 {
		return fmt.Errorf("%s TLS peer sent no certificates", peer)
	}
	leaf, err := x509.ParseCertificate(rawCertificates[0])
	if err != nil {
		return fmt.Errorf("parse %s TLS peer leaf: %w", peer, err)
	}
	if certificateFingerprint(leaf) != expected {
		return fmt.Errorf("%s TLS peer leaf fingerprint does not match published material", peer)
	}
	return nil
}
