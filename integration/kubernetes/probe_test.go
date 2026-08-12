package kubernetes

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"k8s.io/client-go/rest"
)

func TestWebhookAdmissionCanaryUsesDryRunSandboxPoolUpdate(t *testing.T) {
	requests := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		path := "/apis/sandbox.zeist.io/v1alpha1/sandboxpools/" + webhookCanaryPoolName
		if request.Method == http.MethodGet && request.URL.Path == path {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"apiVersion":"sandbox.zeist.io/v1alpha1","kind":"SandboxPool","metadata":{"name":"zeist-pki-rotation-canary","resourceVersion":"42"},"spec":{"runtime":"base","resourceClass":{"cpu":"500m","memory":"1Gi","storage":"5Gi"},"capacitySpec":{"bufferMin":0,"bufferMax":0}},"status":{"observedGeneration":1}}`)), Request: request}, nil
		}
		if request.Method != http.MethodPut || request.URL.Path != path || request.URL.Query().Get("dryRun") != "All" {
			return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(`{"message":"wrong request"}`)), Request: request}, nil
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]any
		if err := json.Unmarshal(body, &object); err != nil {
			t.Fatal(err)
		}
		metadata, _ := object["metadata"].(map[string]any)
		spec, _ := object["spec"].(map[string]any)
		annotations, _ := metadata["annotations"].(map[string]any)
		status, _ := object["status"].(map[string]any)
		if object["kind"] != "SandboxPool" || metadata["name"] != webhookCanaryPoolName || metadata["resourceVersion"] != "42" || annotations["pki.zeist.io/rotation-canary"] == "" || spec["runtime"] != "base" || status["observedGeneration"] != float64(1) {
			return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(`{"message":"wrong object"}`)), Request: request}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`)), Request: request}, nil
	})

	canary, err := NewWebhookAdmissionCanary(&rest.Config{
		Host: "https://api.example.test", Transport: transport,
	}, []string{"https://api.example.test", "https://api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := canary(context.Background()); err != nil {
		t.Fatalf("canary: %v", err)
	}
	if requests != 2 {
		t.Fatalf("canary requests = %d, want one GET and one dry-run update", requests)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestWebhookAdmissionCanaryRejectsNonOriginConfiguredEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"http://api.example.test",
		"https://user@api.example.test",
		"https://api.example.test/path",
		"https://api.example.test?",
	} {
		if _, err := NewWebhookAdmissionCanary(&rest.Config{Host: "https://api.example.test"}, []string{endpoint}); err == nil {
			t.Fatalf("canary accepted non-origin endpoint %q", endpoint)
		}
	}
}

func TestNodeStatusEndpointBracketsIPv6InternalIP(t *testing.T) {
	endpoint, err := nodeStatusEndpoint("2001:db8::42", "10443", 10443)
	if err != nil {
		t.Fatalf("nodeStatusEndpoint() error = %v", err)
	}
	if want := "https://[2001:db8::42]:10443/v2/status"; endpoint != want {
		t.Fatalf("nodeStatusEndpoint() = %q, want %q", endpoint, want)
	}
}

func TestNodeStatusEndpointRejectsInvalidNodeEvidence(t *testing.T) {
	for _, test := range []struct {
		name string
		ip   string
		port string
	}{
		{name: "not an IP", ip: "node.example.test", port: "10443"},
		{name: "zero port", ip: "192.0.2.10", port: "0"},
		{name: "non-numeric port", ip: "192.0.2.10", port: "not-a-port"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := nodeStatusEndpoint(test.ip, test.port, 10443); err == nil {
				t.Fatal("nodeStatusEndpoint() succeeded for invalid node evidence")
			}
		})
	}
}
