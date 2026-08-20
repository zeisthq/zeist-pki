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
`))
	f.Add([]byte("not: [valid"))

	f.Fuzz(func(t *testing.T, document []byte) {
		_, _ = decodeAndValidate(document)
	})
}
