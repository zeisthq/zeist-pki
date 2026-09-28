package config

import (
	"strings"
	"testing"
)

func TestDomainsAreFixedAndIndependent(t *testing.T) {
	file := File{
		APIVersion: APIVersion, Namespace: "system",
		Webhook: Webhook{
			Service: "webhook", Secret: "webhook-tls",
			CanaryService: "webhook-canary", CanarySecret: "webhook-canary-tls", CanaryConfiguration: "webhook-canary-config",
			PodSelector: map[string]string{"app": "manager"}, ConfigurationNames: []string{"webhook-config"},
			CanaryResourcePath: "/apis/example.io/v1/widgets/canary", CanaryAnnotation: "pki.example.io/canary",
		},
		MTLS: MTLS{ServerSecret: "server", ClientSecret: "client", Service: "runner", NodeSelector: map[string]string{"a": "b"}, ClientPodSelector: map[string]string{"app": "manager"}, ServerPodSelector: map[string]string{"app": "runner"}, Port: 10443},
		ServiceMTLS: []ServiceMTLS{{
			Name: "api", Server: ServiceMTLSServer{Namespace: "api", Service: "api", Secret: "api-tls", PodSelector: map[string]string{"role": "server"}, Port: 443},
			Client: ServiceMTLSClient{Namespace: "client", Secret: "api-client-tls", PodSelector: map[string]string{"role": "client"}},
		}},
	}
	domains, err := file.Domains()
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 3 || domains[0].ConfigurationHash == domains[1].ConfigurationHash || domains[1].ConfigurationHash == domains[2].ConfigurationHash {
		t.Fatalf("domains = %#v, want three independently hashed domains", domains)
	}
}

func TestProbeOnlyPreservesExistingServiceDomainHash(t *testing.T) {
	file := File{
		APIVersion: APIVersion, Namespace: "system",
		ServiceMTLS: []ServiceMTLS{{
			Name: "api",
			Server: ServiceMTLSServer{
				Namespace: "api", Service: "api", Secret: "api-tls",
				PodSelector: map[string]string{"role": "server"}, Port: 443,
			},
			Client: ServiceMTLSClient{
				Namespace: "client", Secret: "api-client-tls",
				PodSelector: map[string]string{"role": "client"},
			},
		}},
	}
	// Generated with the pre-probe-only release. Existing state must keep this hash.
	const oldHash = "sha256:2f031a7b9373c05b25b5c12f865ee00cf8c14cc261c87379dfe3e5c4e6456b37"
	if got := file.DomainHash("api"); got != oldHash {
		t.Fatalf("existing service domain hash = %q, want %q", got, oldHash)
	}
	file.ServiceMTLS[0].Server.ProbeOnly = true
	// Generated with v0.2.4, which first issued probe-only domains.
	const probeOnlyHash = "sha256:b015b2999661243aeb6c375b487cd0fdf02b944c84cdbff0d1ed424e569471d3"
	if got := file.DomainHash("api"); got != probeOnlyHash {
		t.Fatalf("probe-only service domain hash = %q, want %q", got, probeOnlyHash)
	}
}

func TestWebhookCanaryConfigurationIsRequiredAndHashed(t *testing.T) {
	file := File{
		APIVersion: APIVersion, Namespace: "system",
		Webhook: Webhook{
			Service: "webhook", Secret: "webhook-tls",
			CanaryService: "webhook-canary", CanarySecret: "webhook-canary-tls", CanaryConfiguration: "webhook-canary-config",
			APIServerEndpoints: []string{"https://api-1.example.test", "https://api-2.example.test"},
			PodSelector:        map[string]string{"app": "manager"}, ConfigurationNames: []string{"webhook-config"},
			CanaryResourcePath: "/apis/example.io/v1/widgets/canary", CanaryAnnotation: "pki.example.io/canary",
		},
		MTLS: MTLS{ServerSecret: "server", ClientSecret: "client", Service: "runner", NodeSelector: map[string]string{"a": "b"}, ClientPodSelector: map[string]string{"app": "manager"}, ServerPodSelector: map[string]string{"app": "runner"}, Port: 10443},
	}
	if err := file.Validate(); err != nil {
		t.Fatal(err)
	}
	hash := file.DomainHash("webhook")
	changed := file
	changed.Webhook.CanaryConfiguration = "other-canary-config"
	if hash == changed.DomainHash("webhook") {
		t.Fatal("candidate-only webhook configuration did not affect webhook domain hash")
	}
	missing := file
	missing.Webhook.CanarySecret = ""
	if err := missing.Validate(); err == nil {
		t.Fatal("configuration accepted missing canarySecret")
	}
	invalidEndpoint := file
	invalidEndpoint.Webhook.APIServerEndpoints = []string{"https://api.example.test/path"}
	if err := invalidEndpoint.Validate(); err == nil {
		t.Fatal("configuration accepted API-server endpoint path")
	}
	invalidEndpoint.Webhook.APIServerEndpoints = []string{"https://api.example.test?"}
	if err := invalidEndpoint.Validate(); err == nil {
		t.Fatal("configuration accepted API-server endpoint query marker")
	}
}

func TestDecoderRejectsUnknownNestedAndPolicyFields(t *testing.T) {
	base := `apiVersion: pki.zeist.io/v1alpha1
namespace: system
webhook:
  service: webhook
  secret: webhook-tls
  canaryService: webhook-canary
  canarySecret: webhook-canary-tls
  canaryConfiguration: webhook-canary-config
  podSelector: {app: manager}
  configurationNames: [webhook-config]
  canaryResourcePath: /apis/example.io/v1/widgets/canary
  canaryAnnotation: pki.example.io/canary
mtls:
  serverSecret: server-tls
  clientSecret: client-tls
  service: runner
  nodeSelector: {zeist.io/firecracker-capable: "true"}
  clientPodSelector: {app: manager}
  serverPodSelector: {app: runner}
  port: 10443
`
	for _, test := range []struct {
		name     string
		document string
		field    string
	}{
		{
			name:     "nested webhook field",
			document: strings.Replace(base, "  canaryConfiguration: webhook-canary-config\n", "  canaryConfiguration: webhook-canary-config\n  unknownWebhookField: true\n", 1),
			field:    "unknownWebhookField",
		},
		{
			name:     "policy field",
			document: base + "policy:\n  leafRenewelBefore: 720h\n",
			field:    "leafRenewelBefore",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeAndValidate([]byte(test.document))
			if err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("decodeAndValidate() error = %v, want unknown field %q", err, test.field)
			}
		})
	}
}

func TestLegacyDomainHashesRemainStableWhileBindingsFenceChanges(t *testing.T) {
	file := File{
		APIVersion: APIVersion, Namespace: "system", AcknowledgementNamespace: "acks",
		Webhook: Webhook{
			Service: "webhook", Secret: "webhook-tls", CanaryService: "canary", CanarySecret: "canary-tls", CanaryConfiguration: "canary-config",
			PodSelector: map[string]string{"app": "manager"}, ConfigurationNames: []string{"production-config"},
			CanaryResourcePath: "/apis/example.io/v1/widgets/canary", CanaryAnnotation: "pki.example.io/canary",
		},
		MTLS: MTLS{
			ServerSecret: "server", ClientSecret: "client", Service: "runner", NodeSelector: map[string]string{"node": "true"},
			ClientPodSelector: map[string]string{"app": "manager"}, ServerPodSelector: map[string]string{"app": "runner"}, Port: 10443,
		},
	}
	legacyHash := file.DomainHash("mtls")
	bindingHash := file.BindingHash("mtls")
	file.MTLS.Service = "other-runner"
	if file.DomainHash("mtls") != legacyHash {
		t.Fatal("runtime binding changed the legacy state configuration hash")
	}
	if file.BindingHash("mtls") == bindingHash {
		t.Fatal("runtime binding did not change the target binding hash")
	}
}

func TestServiceMTLSRejectsUnsafeResourceIdentities(t *testing.T) {
	service := ServiceMTLS{
		Name: "api", Server: ServiceMTLSServer{Namespace: "system", Service: "api", Secret: "shared", PodSelector: map[string]string{"role": "server"}, Port: 443},
		Client: ServiceMTLSClient{Namespace: "system", Secret: "shared", PodSelector: map[string]string{"role": "client"}},
	}
	if err := service.Validate(); err == nil || !strings.Contains(err.Error(), "must be different") {
		t.Fatalf("Validate() error = %v, want shared Secret rejection", err)
	}
	service.Client.Secret = "client"
	service.Name = strings.Repeat("a", 33)
	if err := service.Validate(); err == nil || !strings.Contains(err.Error(), "at most 32") {
		t.Fatalf("Validate() error = %v, want Lease-safe domain rejection", err)
	}
}
