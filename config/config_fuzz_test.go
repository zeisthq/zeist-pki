package config

import "testing"

func FuzzFileDecoding(f *testing.F) {
	f.Add([]byte(`apiVersion: pki.zeist.io/v1alpha1
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
`))
	f.Add([]byte("not: [valid"))

	f.Fuzz(func(t *testing.T, document []byte) {
		_, _ = decodeAndValidate(document)
	})
}
