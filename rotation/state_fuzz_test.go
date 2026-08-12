package rotation

import (
	"encoding/json"
	"testing"
	"time"
)

func FuzzStateDecoding(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":"pki.zeist.io/v1alpha1","configurationHash":"sha256:test","phase":"Stable","operationID":"operation","active":{"fingerprint":"sha256:root","notAfter":"2040-01-01T00:00:00Z"},"desiredGeneration":1,"publishedGeneration":1}`))
	f.Add([]byte("not JSON"))

	domain := Domain{
		Name:              "webhook",
		Profile:           ProfileWebhook,
		ConfigurationHash: "sha256:test",
		Policy:            DefaultPolicy(),
	}
	f.Fuzz(func(t *testing.T, document []byte) {
		var state State
		if err := json.Unmarshal(document, &state); err != nil {
			return
		}
		_, _ = PlanAt(domain, &state, time.Now().UTC())
	})
}
