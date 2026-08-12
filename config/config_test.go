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
		},
		MTLS: MTLS{ServerSecret: "server", ClientSecret: "client", NodeSelector: map[string]string{"a": "b"}, Port: 10443},
	}
	domains, err := file.Domains()
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 || domains[0].ConfigurationHash == domains[1].ConfigurationHash {
		t.Fatalf("domains = %#v, want two independently hashed domains", domains)
	}
}

func TestWebhookCanaryConfigurationIsRequiredAndHashed(t *testing.T) {
	file := File{
		APIVersion: APIVersion, Namespace: "system",
		Webhook: Webhook{
			Service: "webhook", Secret: "webhook-tls",
			CanaryService: "webhook-canary", CanarySecret: "webhook-canary-tls", CanaryConfiguration: "webhook-canary-config",
			APIServerEndpoints: []string{"https://api-1.example.test", "https://api-2.example.test"},
		},
		MTLS: MTLS{ServerSecret: "server", ClientSecret: "client", NodeSelector: map[string]string{"a": "b"}, Port: 10443},
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
mtls:
  serverSecret: server-tls
  clientSecret: client-tls
  nodeSelector: {zeist.io/firecracker-capable: "true"}
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
