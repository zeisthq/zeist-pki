package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/zeisthq/zeist-pki/rotation"
)

type fakeRuntime struct {
	states       map[string]rotation.VersionedState
	loadErr      error
	applyCalls   int
	applied      []string
	applyErrors  []error
	onApply      func(int)
	recoverCalls []string
	verifyAcks   []rotation.Acknowledgement
}

func (r *fakeRuntime) Load(_ context.Context, domain string) (rotation.VersionedState, error) {
	if r.loadErr != nil {
		return rotation.VersionedState{}, r.loadErr
	}
	state, found := r.states[domain]
	if !found {
		return rotation.VersionedState{}, rotation.ErrStateNotFound
	}
	return state, nil
}

func (r *fakeRuntime) Apply(_ context.Context, domain rotation.Domain) (rotation.Result, error) {
	r.applyCalls++
	r.applied = append(r.applied, domain.Name)
	if r.onApply != nil {
		r.onApply(r.applyCalls)
	}
	if r.applyCalls <= len(r.applyErrors) && r.applyErrors[r.applyCalls-1] != nil {
		return rotation.Result{}, r.applyErrors[r.applyCalls-1]
	}
	state := r.states[domain.Name].State
	return rotation.Result{State: state, Plan: rotation.Plan{Domain: domain.Name, Phase: state.Phase}}, nil
}

func (r *fakeRuntime) Verify(_ context.Context, _ rotation.VerificationRequest) ([]rotation.Acknowledgement, error) {
	return r.verifyAcks, nil
}

func (r *fakeRuntime) Recover(_ context.Context, domain rotation.Domain, _ string) (rotation.Result, error) {
	r.recoverCalls = append(r.recoverCalls, domain.Name)
	state := r.states[domain.Name].State
	return rotation.Result{State: state, Plan: rotation.Plan{Domain: domain.Name, Phase: state.Phase}}, nil
}

func testDomain(name string) rotation.Domain {
	return rotation.Domain{
		Name: name, Profile: rotation.ProfileWebhook, ConfigurationHash: "sha256:" + name, Policy: rotation.DefaultPolicy(),
	}
}

func testState(domain rotation.Domain) rotation.State {
	now := time.Now().UTC()
	return rotation.State{
		SchemaVersion:          rotation.StateSchemaVersion,
		ConfigurationHash:      domain.ConfigurationHash,
		Phase:                  rotation.PhaseStable,
		OperationID:            "operation-1",
		Active:                 rotation.Root{Fingerprint: "root-fingerprint", NotAfter: now.Add(365 * 24 * time.Hour), Opaque: "PRIVATE-PEM-SENTINEL"},
		LeafNotAfter:           now.Add(90 * 24 * time.Hour),
		DesiredGeneration:      1,
		PublishedGeneration:    1,
		AcknowledgedGeneration: 1,
		Targets:                []rotation.Target{{ID: "target", Evidence: map[string]string{"role": "webhook"}}},
		PublishedMaterials: map[string]rotation.MaterialFingerprint{
			"webhook": {LeafFingerprint: "leaf-fingerprint", TrustFingerprint: "trust-fingerprint"},
		},
	}
}

func TestPlanDoesNotApplyOrGenerateMaterial(t *testing.T) {
	domain := testDomain("webhook")
	runtime := &fakeRuntime{states: map[string]rotation.VersionedState{}}
	plans, err := plansForDomains(context.Background(), runtime, []rotation.Domain{domain})
	if err != nil {
		t.Fatalf("plansForDomains() error = %v", err)
	}
	if runtime.applyCalls != 0 {
		t.Fatalf("plan called Apply %d times", runtime.applyCalls)
	}
	if len(plans) != 1 || len(plans[0].Actions) == 0 || plans[0].Actions[0] != rotation.ActionBootstrapRoot {
		t.Fatalf("plan = %#v, want bootstrap preview", plans)
	}
}

func TestRecoverRequiresExplicitDomainAndConfirmation(t *testing.T) {
	_, err := parseCommand([]string{"recover", "--config", "pki.yaml"})
	if err == nil || !strings.Contains(err.Error(), "--domain") {
		t.Fatalf("parse recover error = %v, want domain requirement", err)
	}
	_, err = parseCommand([]string{"recover", "--config", "pki.yaml", "--domain", "webhook"})
	if err == nil || !strings.Contains(err.Error(), "confirm-active-root-fingerprint") {
		t.Fatalf("parse recover error = %v, want confirmation requirement", err)
	}
	options, err := parseCommand([]string{"recover", "--config", "pki.yaml", "--domain", "webhook", "--confirm-active-root-fingerprint", "webhook=abc"})
	if err != nil {
		t.Fatalf("parse confirmed recover: %v", err)
	}
	if len(options.domains) != 1 || options.domains[0] != "webhook" || len(options.confirmations) != 1 || options.confirmations[0] != "webhook=abc" {
		t.Fatalf("recover options = %#v", options)
	}
	if _, err := parseCommand([]string{"plan", "--config", "pki.yaml", "--domain", "webhook"}); err == nil {
		t.Fatal("plan accepted apply-and-recover-only --domain")
	}
}

func TestApplyAcceptsDomainSelectionButRunAlwaysUsesAllDomains(t *testing.T) {
	options, err := parseCommand([]string{"apply", "--config", "pki.yaml", "--domain", "bucket-broker-lease", "--domain", "bucket-broker-bind"})
	if err != nil {
		t.Fatalf("parse selected apply: %v", err)
	}
	if got := strings.Join(options.domains, ","); got != "bucket-broker-lease,bucket-broker-bind" {
		t.Fatalf("apply domains = %q, want command-line values retained for validated selection", got)
	}
	if _, err := parseCommand([]string{"run", "--config", "pki.yaml", "--domain", "bucket-broker-bind"}); err == nil || !strings.Contains(err.Error(), "always reconciles every configured domain") {
		t.Fatalf("parse partial run error = %v, want all-domains requirement", err)
	}
}

func TestOfflineIsRestrictedToReadOnlyPlan(t *testing.T) {
	options, err := parseCommand([]string{"plan", "--config", "pki.yaml", "--offline"})
	if err != nil || !options.offline {
		t.Fatalf("parse offline plan = %#v, %v", options, err)
	}
	if _, err := parseCommand([]string{"apply", "--config", "pki.yaml", "--offline"}); err == nil {
		t.Fatal("offline apply was accepted")
	}
}

func TestRuntimeIdentityIsUniqueWithinOnePod(t *testing.T) {
	t.Setenv("ZEIST_PKI_POD_UID", "pod-uid")
	t.Setenv("POD_UID", "")
	first := runtimeIdentity()
	second := runtimeIdentity()
	if first == second {
		t.Fatalf("runtimeIdentity() reused %q for two invocations", first)
	}
	for _, identity := range []string{first, second} {
		if !strings.HasPrefix(identity, "pod:pod-uid-") {
			t.Fatalf("runtimeIdentity() = %q, want pod identity with invocation suffix", identity)
		}
	}
}

func TestRecoverySelectionAndConfirmationMappingsAreExact(t *testing.T) {
	configured := []rotation.Domain{testDomain("webhook"), testDomain("mtls")}
	domains, err := selectRecoveryDomains([]string{"webhook"}, configured)
	if err != nil {
		t.Fatalf("selectRecoveryDomains() error = %v", err)
	}
	if len(domains) != 1 || domains[0].Name != "webhook" {
		t.Fatalf("selected recovery domains = %#v", domains)
	}
	confirmations, err := confirmationsForDomains([]string{"webhook=one"}, domains)
	if err != nil {
		t.Fatalf("confirmationsForDomains() error = %v", err)
	}
	if confirmations["webhook"] != "one" {
		t.Fatalf("webhook confirmation = %q", confirmations["webhook"])
	}
	if _, err := confirmationsForDomains(nil, domains); err == nil {
		t.Fatal("missing domain confirmation did not fail")
	}
	if _, err := confirmationsForDomains([]string{"webhook=one", "mtls=two"}, domains); err == nil {
		t.Fatal("unselected domain confirmation did not fail")
	}
	if _, err := selectRecoveryDomains([]string{"unknown"}, configured); err == nil {
		t.Fatal("unknown recovery domain did not fail")
	}
	if _, err := selectRecoveryDomains([]string{"webhook", "webhook"}, configured); err == nil {
		t.Fatal("duplicate recovery domain did not fail")
	}
}

func TestConfiguredDomainSelectionIsExactAndCanonical(t *testing.T) {
	configured := []rotation.Domain{
		testDomain("webhook"),
		testDomain("mtls"),
		testDomain("bucket-broker-bind"),
		testDomain("bucket-broker-lease"),
	}
	selected, err := selectConfiguredDomains("apply", []string{"bucket-broker-lease", "bucket-broker-bind"}, configured)
	if err != nil {
		t.Fatalf("selectConfiguredDomains() error = %v", err)
	}
	if got := []string{selected[0].Name, selected[1].Name}; strings.Join(got, ",") != "bucket-broker-bind,bucket-broker-lease" {
		t.Fatalf("selected domains = %v, want configured canonical order", got)
	}
	if _, err := selectConfiguredDomains("apply", []string{"unknown"}, configured); err == nil || !strings.Contains(err.Error(), "unknown configured domain") {
		t.Fatalf("unknown domain error = %v", err)
	}
	if _, err := selectConfiguredDomains("apply", []string{"bucket-broker-bind", "bucket-broker-bind"}, configured); err == nil || !strings.Contains(err.Error(), "duplicate apply domain") {
		t.Fatalf("duplicate domain error = %v", err)
	}

	runtime := &fakeRuntime{states: map[string]rotation.VersionedState{
		"bucket-broker-bind":  {State: testState(configured[2])},
		"bucket-broker-lease": {State: testState(configured[3])},
	}}
	if _, err := applyDomains(context.Background(), runtime, selected); err != nil {
		t.Fatalf("applyDomains() error = %v", err)
	}
	if got := strings.Join(runtime.applied, ","); got != "bucket-broker-bind,bucket-broker-lease" {
		t.Fatalf("applied domains = %q, want exact canonical selection", got)
	}
}

func TestRecoverDomainsOnlyInvokesSelectedDomains(t *testing.T) {
	webhook := testDomain("webhook")
	mtls := testDomain("mtls")
	runtime := &fakeRuntime{states: map[string]rotation.VersionedState{
		webhook.Name: {State: testState(webhook)},
		mtls.Name:    {State: testState(mtls)},
	}}
	results, err := recoverDomains(context.Background(), runtime, []rotation.Domain{webhook}, map[string]string{"webhook": "sha256:root"})
	if err != nil {
		t.Fatalf("recoverDomains() error = %v", err)
	}
	if len(results) != 1 || len(runtime.recoverCalls) != 1 || runtime.recoverCalls[0] != webhook.Name {
		t.Fatalf("recover calls = %#v, results = %#v", runtime.recoverCalls, results)
	}
}

func TestStatusOutputNeverIncludesOpaqueMaterial(t *testing.T) {
	domain := testDomain("webhook")
	runtime := &fakeRuntime{states: map[string]rotation.VersionedState{
		domain.Name: {State: testState(domain), Version: "1"},
	}}
	statuses, err := statusesForDomains(context.Background(), runtime, []rotation.Domain{domain})
	if err != nil {
		t.Fatalf("statusesForDomains() error = %v", err)
	}
	var output bytes.Buffer
	if err := writeCommandOutput(&output, "json", statusOutput{Domains: statuses}); err != nil {
		t.Fatalf("writeCommandOutput() error = %v", err)
	}
	if strings.Contains(output.String(), "PRIVATE-PEM-SENTINEL") {
		t.Fatalf("status leaked opaque material: %s", output.String())
	}
	if !strings.Contains(output.String(), "root-fingerprint") {
		t.Fatalf("status omitted safe operational metadata: %s", output.String())
	}
}

func TestVerifyRejectsIncompleteAcknowledgements(t *testing.T) {
	domain := testDomain("webhook")
	state := testState(domain)
	runtime := &fakeRuntime{states: map[string]rotation.VersionedState{
		domain.Name: {State: state, Version: "1"},
	}}
	_, err := verifyDomains(context.Background(), runtime, []rotation.Domain{domain})
	if err == nil || !strings.Contains(err.Error(), "incomplete acknowledgement") {
		t.Fatalf("verifyDomains() error = %v, want incomplete acknowledgement", err)
	}
	runtime.verifyAcks = []rotation.Acknowledgement{{
		TargetID: "target", Generation: 1, LeafFingerprint: "leaf-fingerprint", TrustFingerprint: "trust-fingerprint",
	}}
	results, err := verifyDomains(context.Background(), runtime, []rotation.Domain{domain})
	if err != nil {
		t.Fatalf("verifyDomains() complete evidence error = %v", err)
	}
	if len(results) != 1 || !results[0].Verified {
		t.Fatalf("verify result = %#v", results)
	}
}

func TestRunJitterNeverShortensInterval(t *testing.T) {
	interval := 5 * time.Minute
	for range 100 {
		delay := runJitter(interval)
		if delay < interval || delay > interval+maxRunJitter {
			t.Fatalf("runJitter(%s) = %s, outside allowed range", interval, delay)
		}
	}
}

func TestRunRetriesAfterApplyFailureWithoutSerializingCredentials(t *testing.T) {
	domain := testDomain("webhook")
	runtime := &fakeRuntime{states: map[string]rotation.VersionedState{
		domain.Name: {State: testState(domain)},
	}, applyErrors: []error{errors.New("PRIVATE-PEM-SENTINEL")}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime.onApply = func(calls int) {
		if calls == 2 {
			cancel()
		}
	}
	var output bytes.Buffer
	application := app{
		interval: time.Millisecond,
		jitter:   func(time.Duration) time.Duration { return time.Millisecond },
	}
	if err := application.run(ctx, runtime, []rotation.Domain{domain}, "json", &output); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if runtime.applyCalls != 2 {
		t.Fatalf("Apply calls = %d, want retry after first failure", runtime.applyCalls)
	}
	if strings.Contains(output.String(), "PRIVATE-PEM-SENTINEL") {
		t.Fatalf("run output leaked adapter error material: %s", output.String())
	}
	decoder := json.NewDecoder(&output)
	var attempts []runOutput
	for {
		var attempt runOutput
		err := decoder.Decode(&attempt)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode run output: %v", err)
		}
		attempts = append(attempts, attempt)
	}
	if len(attempts) != 2 {
		t.Fatalf("run output entries = %d, want failed then successful reconciliation", len(attempts))
	}
	if len(attempts[0].Failures) != 1 || attempts[0].Failures[0].Domain != domain.Name || attempts[0].Failures[0].Message != "reconciliation failed" {
		t.Fatalf("first run output failures = %#v", attempts[0].Failures)
	}
	if len(attempts[1].Failures) != 0 || len(attempts[1].Results) != 1 {
		t.Fatalf("second run output = %#v, want successful reconciliation", attempts[1])
	}
}

func TestRunContinuesOtherDomainWhenOneDomainFails(t *testing.T) {
	webhook := testDomain("webhook")
	mtls := testDomain("mtls")
	runtime := &fakeRuntime{states: map[string]rotation.VersionedState{
		webhook.Name: {State: testState(webhook)},
		mtls.Name:    {State: testState(mtls)},
	}, applyErrors: []error{errors.New("PRIVATE-PEM-SENTINEL"), nil}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime.onApply = func(calls int) {
		if calls == 2 {
			cancel()
		}
	}
	var output bytes.Buffer
	application := app{interval: time.Millisecond, jitter: func(time.Duration) time.Duration { return time.Millisecond }}
	if err := application.run(ctx, runtime, []rotation.Domain{webhook, mtls}, "json", &output); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if runtime.applyCalls != 2 {
		t.Fatalf("Apply calls = %d, want both domains reconciled in the failed cycle", runtime.applyCalls)
	}
	var attempt runOutput
	if err := json.NewDecoder(&output).Decode(&attempt); err != nil {
		t.Fatalf("decode run output: %v", err)
	}
	if len(attempt.Failures) != 1 || attempt.Failures[0].Domain != webhook.Name || len(attempt.Results) != 1 || attempt.Results[0].Domain != mtls.Name {
		t.Fatalf("run output = %#v, want webhook failure and mTLS success", attempt)
	}
	if strings.Contains(output.String(), "PRIVATE-PEM-SENTINEL") {
		t.Fatalf("run output leaked adapter error material: %s", output.String())
	}
}

func TestRunFailureTextOutputIsCredentialFree(t *testing.T) {
	var output bytes.Buffer
	if err := writeCommandOutput(&output, "text", runOutput{
		At: time.Unix(0, 0).UTC(),
		Failures: []runFailure{{
			Domain:  "webhook",
			Message: "reconciliation failed",
		}},
	}); err != nil {
		t.Fatalf("writeCommandOutput() error = %v", err)
	}
	if got := output.String(); strings.Contains(got, "PRIVATE-PEM-SENTINEL") || !strings.Contains(got, "status=retrying domain=webhook failure=\"reconciliation failed\"") {
		t.Fatalf("text run failure output = %q", got)
	}
}

func TestPlanPropagatesUnexpectedStateErrors(t *testing.T) {
	domain := testDomain("webhook")
	want := errors.New("API unavailable")
	runtime := &fakeRuntime{loadErr: want}
	_, err := plansForDomains(context.Background(), runtime, []rotation.Domain{domain})
	if !errors.Is(err, want) {
		t.Fatalf("plansForDomains() error = %v, want wrapped %v", err, want)
	}
}
