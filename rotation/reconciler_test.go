package rotation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPlanAtLifecycleTable(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()

	withCandidate := func(state State) State {
		candidate := Root{Fingerprint: "candidate-root", NotAfter: now.Add(domain.Policy.RootValidity)}
		state.Candidate = &candidate
		return state
	}
	withDeadline := func(state State, deadline time.Time) State {
		state = withCandidate(state)
		state.Phase = PhaseOverlap
		state.MinimumOverlapDeadline = &deadline
		return state
	}

	stable := testStableState(domain, now)
	pending := stable
	pending.DesiredGeneration++
	rootDue := stable
	rootDue.Active.NotAfter = now.Add(domain.Policy.RootRolloverBefore + domain.Policy.ClockSkew - time.Nanosecond)
	leafDue := stable
	leafDue.LeafNotAfter = now.Add(domain.Policy.LeafRenewBefore + domain.Policy.ClockSkew - time.Nanosecond)
	blocked := stable
	blocked.Phase = PhaseBlocked
	blocked.BlockedReason = "waiting for a node"

	tests := []struct {
		name    string
		state   *State
		phase   Phase
		actions []ActionKind
		reason  string
	}{
		{
			name:    "fresh domain bootstraps root and leaves",
			phase:   PhaseStable,
			actions: []ActionKind{ActionBootstrapRoot, ActionRenewLeaves},
		},
		{
			name:  "healthy stable state is quiet",
			state: &stable,
			phase: PhaseStable,
		},
		{
			name:    "unpublished desired generation resumes leaf publication",
			state:   &pending,
			phase:   PhaseStable,
			actions: []ActionKind{ActionRenewLeaves},
		},
		{
			name:    "root threshold begins rollover",
			state:   &rootDue,
			phase:   PhaseStable,
			actions: []ActionKind{ActionBeginRootRollover, ActionPublishDualTrust},
		},
		{
			name:    "leaf threshold renews leaves",
			state:   &leafDue,
			phase:   PhaseStable,
			actions: []ActionKind{ActionRenewLeaves},
		},
		{
			name:    "dual trust awaits proof",
			state:   ptrState(withCandidate(State{SchemaVersion: StateSchemaVersion, ConfigurationHash: domain.ConfigurationHash, Phase: PhaseAwaitingDualTrust, Active: stable.Active, DesiredGeneration: 2, PublishedGeneration: 2})),
			phase:   PhaseAwaitingDualTrust,
			actions: []ActionKind{ActionVerifyDualTrust},
		},
		{
			name:    "overlap before deadline does not retire",
			state:   ptrState(withDeadline(stable, now.Add(time.Hour))),
			phase:   PhaseOverlap,
			actions: []ActionKind{ActionMaintainOverlap},
		},
		{
			name:    "overlap at deadline starts retirement",
			state:   ptrState(withDeadline(stable, now)),
			phase:   PhaseOverlap,
			actions: []ActionKind{ActionRetireActiveRoot},
		},
		{
			name:    "blocked state remains blocked",
			state:   &blocked,
			phase:   PhaseBlocked,
			actions: []ActionKind{ActionBlocked},
			reason:  blocked.BlockedReason,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := PlanAt(domain, tt.state, now)
			if err != nil {
				t.Fatalf("PlanAt() error = %v", err)
			}
			if plan.Domain != domain.Name || plan.Phase != tt.phase {
				t.Fatalf("PlanAt() = %#v, want domain %q and phase %q", plan, domain.Name, tt.phase)
			}
			if !reflect.DeepEqual(plan.Actions, tt.actions) {
				t.Fatalf("PlanAt().Actions = %#v, want %#v", plan.Actions, tt.actions)
			}
			if plan.BlockedReason != tt.reason {
				t.Fatalf("PlanAt().BlockedReason = %q, want %q", plan.BlockedReason, tt.reason)
			}
		})
	}
}

func TestPlanAtStartsAtConfiguredExpiryBoundary(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()

	tests := []struct {
		name  string
		state State
		want  []ActionKind
	}{
		{
			name: "root rollover boundary is inclusive",
			state: func() State {
				state := testStableState(domain, now)
				state.Active.NotAfter = now.Add(domain.Policy.RootRolloverBefore + domain.Policy.ClockSkew)
				return state
			}(),
			want: []ActionKind{ActionBeginRootRollover, ActionPublishDualTrust},
		},
		{
			name: "leaf renewal boundary is inclusive",
			state: func() State {
				state := testStableState(domain, now)
				state.LeafNotAfter = now.Add(domain.Policy.LeafRenewBefore + domain.Policy.ClockSkew)
				return state
			}(),
			want: []ActionKind{ActionRenewLeaves},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := PlanAt(domain, &tt.state, now)
			if err != nil {
				t.Fatalf("PlanAt() error = %v", err)
			}
			if !reflect.DeepEqual(plan.Actions, tt.want) {
				t.Fatalf("PlanAt().Actions = %#v, want %#v", plan.Actions, tt.want)
			}
		})
	}
}

func TestPlanAtRejectsInvalidDomainAndState(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	valid := testStableState(domain, now)

	tests := []struct {
		name   string
		domain Domain
		state  *State
		want   string
	}{
		{
			name:   "domain configuration hash is required",
			domain: func() Domain { d := domain; d.ConfigurationHash = ""; return d }(),
			want:   "configuration hash is required",
		},
		{
			name:   "state configuration hash must match",
			domain: domain,
			state:  ptrState(func() State { s := valid; s.ConfigurationHash = "sha256:other"; return s }()),
			want:   "configuration hash does not match",
		},
		{
			name:   "state schema must match",
			domain: domain,
			state:  ptrState(func() State { s := valid; s.SchemaVersion = "pki.zeist.io/v0"; return s }()),
			want:   "unsupported state schema",
		},
		{
			name:   "rollover phase requires a candidate",
			domain: domain,
			state:  ptrState(func() State { s := valid; s.Phase = PhaseAwaitingDualTrust; return s }()),
			want:   "requires a candidate root",
		},
		{
			name:   "candidate activation proof may verify an ordinary renewal",
			domain: domain,
			state: ptrState(func() State {
				s := valid
				s.Phase = PhaseAwaitingCandidateActivation
				return s
			}()),
		},
		{
			name:   "candidate must be complete",
			domain: domain,
			state:  ptrState(func() State { s := valid; candidate := Root{}; s.Candidate = &candidate; return s }()),
			want:   "candidate root is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PlanAt(tt.domain, tt.state, now)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("PlanAt() error = %v, want ordinary-renewal verification state accepted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("PlanAt() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestReconcilerBootstrapPersistsBeforePublicIssuance(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	h := newRotationHarness(now, nil)

	result, err := h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.State.Phase != PhaseAwaitingCandidateActivation {
		t.Fatalf("phase = %q, want %q", result.State.Phase, PhaseAwaitingCandidateActivation)
	}
	if len(h.issuer.roots) != 1 || len(h.issuer.issues) != 1 || len(h.publisher.publications) != 1 {
		t.Fatalf("roots=%d issues=%d publications=%d, want one each", len(h.issuer.roots), len(h.issuer.issues), len(h.publisher.publications))
	}
	if len(h.store.saves) < 2 {
		t.Fatalf("state saves = %d, want bootstrap authority plus publication intent/state", len(h.store.saves))
	}
	if got := h.store.saves[0]; got.Active.Fingerprint != h.issuer.roots[0].Fingerprint || got.DesiredGeneration != 1 || got.PublishedGeneration != 0 {
		t.Fatalf("bootstrap state = %#v, want persisted root authority before publication", got)
	}
	if got, want := eventIndex(h.events, "store.save:Stable:1"), eventIndex(h.events, "issuer.issue:1"); got < 0 || want < 0 || got >= want {
		t.Fatalf("events = %#v, want bootstrap save before issuance", h.events)
	}
	if got, want := eventIndex(h.events, "store.save:Stable:1"), eventIndex(h.events, "publisher.publish:1"); got < 0 || want < 0 || got >= want {
		t.Fatalf("events = %#v, want bootstrap save before public distribution", h.events)
	}
	result, err = h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("verification Apply() error = %v", err)
	}
	if result.State.Phase != PhaseStable || result.State.AcknowledgedGeneration != 1 {
		t.Fatalf("verification result = %#v, want acknowledged stable bootstrap generation", result.State)
	}
}

func TestReconcilerRenewsLeafAfterPersistingGenerationIntent(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	state := testStableState(domain, now)
	state.LeafNotAfter = now.Add(domain.Policy.LeafRenewBefore - time.Minute)
	state.Targets = []Target{{ID: "consumer"}}
	h := newRotationHarness(now, &state)

	result, err := h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.State.Phase != PhaseAwaitingCandidateActivation || result.State.DesiredGeneration != 2 || result.State.PublishedGeneration != 2 {
		t.Fatalf("result state = %#v, want published renewal generation 2 awaiting proof", result.State)
	}
	if len(h.store.saves) != 2 || h.store.saves[0].DesiredGeneration != 2 || h.store.saves[0].PublishedGeneration != 1 {
		t.Fatalf("state saves = %#v, want durable generation intent before publish", h.store.saves)
	}
	if len(h.issuer.issues) != 1 || h.issuer.issues[0].Signer.Fingerprint != state.Active.Fingerprint || h.issuer.issues[0].DualTrust || h.issuer.issues[0].Generation != 2 {
		t.Fatalf("leaf issuance = %#v, want active-root single-trust generation 2", h.issuer.issues)
	}
	if got, want := eventIndex(h.events, "store.save:Stable:2"), eventIndex(h.events, "publisher.publish:2"); got < 0 || want < 0 || got >= want {
		t.Fatalf("events = %#v, want leaf renewal intent saved before publication", h.events)
	}
	result, err = h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("renewal verification Apply() error = %v", err)
	}
	if result.State.Phase != PhaseStable || result.State.AcknowledgedGeneration != 2 {
		t.Fatalf("renewal verification result = %#v, want acknowledged stable generation 2", result.State)
	}
}

func TestReconcilerTargetChangePersistsSnapshotBeforeReissuingLeaves(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	state := testStableState(domain, now)
	state.Targets = []Target{{ID: "zeistd/node-old", Evidence: map[string]string{"internalIP": "192.0.2.10"}}}
	h := newRotationHarness(now, &state)
	h.discoverer.targets = []Target{{ID: "zeistd/node-new", Evidence: map[string]string{"internalIP": "192.0.2.11"}}}

	result, err := h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.State.Phase != PhaseAwaitingCandidateActivation || result.State.DesiredGeneration != 2 || result.State.PublishedGeneration != 2 {
		t.Fatalf("result state = %#v, want reissued generation 2 awaiting target activation", result.State)
	}
	if len(h.store.saves) < 2 {
		t.Fatalf("state saves = %#v, want durable target snapshot and publication state", h.store.saves)
	}
	intent := h.store.saves[0]
	if intent.DesiredGeneration != 2 || intent.PublishedGeneration != 1 || !reflect.DeepEqual(intent.Targets, h.discoverer.targets) {
		t.Fatalf("target-change intent = %#v, want generation 2 and discovered target snapshot %#v", intent, h.discoverer.targets)
	}
	if len(h.issuer.issues) != 1 || !reflect.DeepEqual(h.issuer.issues[0].Targets, h.discoverer.targets) {
		t.Fatalf("issuance request = %#v, want the persisted new target snapshot", h.issuer.issues)
	}
	if save, issue := eventIndex(h.events, "store.save:Stable:2"), eventIndex(h.events, "issuer.issue:2"); save < 0 || issue < 0 || save >= issue {
		t.Fatalf("events = %#v, want target snapshot saved before leaf issuance", h.events)
	}
}

func TestReconcilerRefreshesServiceTargetsWithoutReissuingLeaves(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	domain.Name = "service"
	domain.Profile = ProfileServiceMTLS
	state := testStableState(domain, now)
	state.Targets = []Target{{ID: "pod:server:old"}}
	h := newRotationHarness(now, &state)
	h.domain = domain
	h.discoverer.targets = []Target{{ID: "pod:server:new"}}

	refreshed, err := h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("target refresh Apply() error = %v", err)
	}
	if refreshed.State.Phase != PhaseAwaitingCandidateActivation || refreshed.State.DesiredGeneration != 1 || refreshed.State.PublishedGeneration != 1 {
		t.Fatalf("refreshed state = %#v, want same published generation awaiting target proof", refreshed.State)
	}
	if !reflect.DeepEqual(refreshed.State.Targets, h.discoverer.targets) {
		t.Fatalf("refreshed targets = %#v, want %#v", refreshed.State.Targets, h.discoverer.targets)
	}
	if len(h.issuer.issues) != 0 || len(h.publisher.publications) != 0 {
		t.Fatalf("service target refresh issued=%d published=%d, want no new material", len(h.issuer.issues), len(h.publisher.publications))
	}

	verified, err := h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("target refresh verification error = %v", err)
	}
	if verified.State.Phase != PhaseStable || verified.State.AcknowledgedGeneration != 1 {
		t.Fatalf("verified state = %#v, want stable acknowledged generation 1", verified.State)
	}
}

func TestReconcilerRejectsDuplicateDiscoveredTargetsBeforeIssuance(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	state := testStableState(domain, now)
	state.LeafNotAfter = now.Add(domain.Policy.LeafRenewBefore - time.Minute)
	h := newRotationHarness(now, &state)
	h.discoverer.targets = []Target{{ID: "consumer"}, {ID: "consumer"}}

	if _, err := h.reconciler.Apply(context.Background(), h.domain); err == nil || !strings.Contains(err.Error(), "duplicate target ID") {
		t.Fatalf("Apply() error = %v, want duplicate target rejection", err)
	}
	if len(h.issuer.issues) != 0 || len(h.publisher.publications) != 0 {
		t.Fatalf("duplicate target discovery issued=%d published=%d, want no external effect", len(h.issuer.issues), len(h.publisher.publications))
	}
}

func TestTargetsEqualRejectsDuplicateSecondSnapshot(t *testing.T) {
	if targetsEqual([]Target{{ID: "manager"}, {ID: "node"}}, []Target{{ID: "manager"}, {ID: "manager"}}) {
		t.Fatal("targetsEqual accepted a duplicate target in the second snapshot")
	}
}

func TestReconcilerRestartsDualTrustWhenTargetChangesBeforeCandidateLeafIssue(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	state := testStableState(domain, now)
	candidate := Root{Fingerprint: "candidate-root", NotAfter: now.Add(domain.Policy.RootValidity)}
	oldTargets := []Target{{ID: "manager:old"}}
	newTargets := []Target{{ID: "manager:new"}}
	state.Phase = PhaseActivatingCandidateLeaves
	state.Candidate = &candidate
	state.DesiredGeneration = 2
	state.PublishedGeneration = 2
	state.PublishedDualTrust = true
	state.Targets = oldTargets
	h := newRotationHarness(now, &state)
	h.discoverer.targets = newTargets

	result, err := h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("Apply() candidate activation = %v", err)
	}
	if result.State.Phase != PhasePublishingDualTrust || result.State.DesiredGeneration != 3 || result.State.PublishedGeneration != 2 {
		t.Fatalf("target-change state = %#v, want new dual-trust intent", result.State)
	}
	if len(h.issuer.issues) != 0 || len(h.publisher.publications) != 0 {
		t.Fatalf("candidate activation issued=%d published=%d, want no candidate leaf for an unproven target", len(h.issuer.issues), len(h.publisher.publications))
	}

	result, err = h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("Apply() replacement dual trust = %v", err)
	}
	if result.State.Phase != PhaseAwaitingDualTrust || len(h.issuer.issues) != 1 {
		t.Fatalf("replacement state = %#v issues=%#v", result.State, h.issuer.issues)
	}
	issue := h.issuer.issues[0]
	if issue.Signer.Fingerprint != state.Active.Fingerprint || !issue.DualTrust || !reflect.DeepEqual(issue.Targets, newTargets) {
		t.Fatalf("replacement issue = %#v, want active-signed dual trust for %#v", issue, newTargets)
	}
}

func TestReconcilerRestartsDualTrustWhenTargetChangesDuringCandidateActivationProof(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	state := testStableState(domain, now)
	candidate := Root{Fingerprint: "candidate-root", NotAfter: now.Add(domain.Policy.RootValidity)}
	oldTargets := []Target{{ID: "manager:old"}}
	newTargets := []Target{{ID: "manager:new"}}
	state.Phase = PhaseAwaitingCandidateActivation
	state.Candidate = &candidate
	state.DesiredGeneration = 3
	state.PublishedGeneration = 3
	state.PublishedDualTrust = true
	state.Targets = oldTargets
	h := newRotationHarness(now, &state)
	h.discoverer.targets = newTargets

	result, err := h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("Apply() candidate activation proof = %v", err)
	}
	if result.State.Phase != PhasePublishingDualTrust || result.State.DesiredGeneration != 4 || result.State.PublishedGeneration != 0 {
		t.Fatalf("target-change proof state = %#v, want replacement dual-trust intent", result.State)
	}
	if len(h.verifier.calls) != 0 || len(h.issuer.issues) != 0 || len(h.publisher.publications) != 0 {
		t.Fatalf("proof target change verify=%d issue=%d publish=%d, want no advancement", len(h.verifier.calls), len(h.issuer.issues), len(h.publisher.publications))
	}

	result, err = h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("Apply() replacement dual trust = %v", err)
	}
	if result.State.Phase != PhaseAwaitingDualTrust || len(h.issuer.issues) != 1 {
		t.Fatalf("replacement state = %#v issues=%#v", result.State, h.issuer.issues)
	}
	issue := h.issuer.issues[0]
	if issue.Signer.Fingerprint != state.Active.Fingerprint || !issue.DualTrust || !reflect.DeepEqual(issue.Targets, newTargets) {
		t.Fatalf("replacement issue = %#v, want active-signed dual trust for %#v", issue, newTargets)
	}
}

func TestReconcilerRootRolloverRequiresProofAndOverlapBeforeRetirement(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	state := testStableState(domain, now)
	state.Active.NotAfter = now.Add(domain.Policy.RootRolloverBefore + domain.Policy.ClockSkew - time.Minute)
	state.Targets = []Target{{ID: "manager"}, {ID: "zeistd/node-a"}}
	h := newRotationHarness(now, &state)
	h.discoverer.targets = []Target{{ID: "manager"}, {ID: "zeistd/node-a"}}
	h.verifier.verify = acknowledgementsForAllTargets

	apply := func(want Phase) Result {
		t.Helper()
		result, err := h.reconciler.Apply(context.Background(), h.domain)
		if err != nil {
			t.Fatalf("Apply() error = %v", err)
		}
		if result.State.Phase != want {
			t.Fatalf("phase = %q, want %q; state=%#v", result.State.Phase, want, result.State)
		}
		return result
	}

	apply(PhasePublishingDualTrust)
	if len(h.issuer.roots) != 1 || len(h.publisher.publications) != 0 {
		t.Fatalf("candidate creation roots=%d publications=%d, want persisted candidate but no publication", len(h.issuer.roots), len(h.publisher.publications))
	}
	candidate := *h.store.state.Candidate
	apply(PhaseAwaitingDualTrust)
	if got := h.publisher.publications[0]; !got.DualTrust || got.Generation != 2 {
		t.Fatalf("dual-trust publication = %#v, want dual generation 2", got)
	}
	if got := h.issuer.issues[0]; got.Signer.Fingerprint != state.Active.Fingerprint || !got.DualTrust || got.Generation != 2 {
		t.Fatalf("dual-trust leaf request = %#v, want active-root-signed dual-trust generation 2", got)
	}
	apply(PhaseActivatingCandidateLeaves)
	apply(PhaseAwaitingCandidateActivation)
	if got := h.issuer.issues[len(h.issuer.issues)-1]; got.Signer.Fingerprint != candidate.Fingerprint || !got.DualTrust || got.Generation != 3 {
		t.Fatalf("candidate leaf request = %#v, want candidate-signed dual-trust generation 3", got)
	}
	overlap := apply(PhaseOverlap)
	if overlap.State.MinimumOverlapDeadline == nil {
		t.Fatal("overlap state has no persisted deadline")
	}

	h.now = overlap.State.MinimumOverlapDeadline.Add(-time.Nanosecond)
	apply(PhaseOverlap)
	if len(h.issuer.retired) != 0 {
		t.Fatalf("retired roots = %#v before overlap deadline", h.issuer.retired)
	}

	h.now = *overlap.State.MinimumOverlapDeadline
	apply(PhaseRetiringActiveRoot)
	if len(h.issuer.retired) != 0 {
		t.Fatalf("retired roots = %#v before candidate-only publication and proof", h.issuer.retired)
	}
	apply(PhaseRetiringActiveRoot)
	if got := h.publisher.publications[len(h.publisher.publications)-1]; got.DualTrust || got.Generation != 4 {
		t.Fatalf("retirement publication = %#v, want candidate-only generation 4", got)
	}
	if got := h.issuer.issues[len(h.issuer.issues)-1]; len(got.Targets) != 2 || got.Targets[0].ID != "manager" || got.Targets[1].ID != "zeistd/node-a" {
		t.Fatalf("candidate-only issue targets = %#v, want current durable target snapshot", got.Targets)
	}
	// Candidate-only evidence is persisted as destructive-operation authority
	// before the old root is touched; the following bounded reconcile performs
	// the idempotent retirement.
	authorized := apply(PhaseRetiringActiveRoot)
	if !authorized.State.RetirementAuthorized || len(h.issuer.retired) != 0 {
		t.Fatalf("retirement authorization = %#v, retired=%#v; want durable authorization before deletion", authorized.State, h.issuer.retired)
	}
	final := apply(PhaseStable)
	if len(h.issuer.retired) != 1 || h.issuer.retired[0].Fingerprint != state.Active.Fingerprint {
		t.Fatalf("retired roots = %#v, want only original active root", h.issuer.retired)
	}
	if final.State.Active.Fingerprint != candidate.Fingerprint || final.State.Candidate != nil || final.State.MinimumOverlapDeadline != nil {
		t.Fatalf("final state = %#v, want candidate active and no rollover residue", final.State)
	}
}

func TestReconcilerRestartsDualTrustWhenTargetsChangeDuringOverlap(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	state := testStableState(domain, now)
	candidate := Root{Fingerprint: "candidate-root", NotAfter: now.Add(domain.Policy.RootValidity)}
	deadline := now.Add(time.Hour)
	oldTargets := []Target{{ID: "manager:old"}, {ID: "node:old"}}
	newTargets := []Target{{ID: "manager:new"}, {ID: "node:new"}}
	state.Phase = PhaseOverlap
	state.Candidate = &candidate
	state.OperationID = "candidate-activation"
	state.DesiredGeneration = 3
	state.PublishedGeneration = 3
	state.PublishedDualTrust = true
	state.Targets = oldTargets
	state.MinimumOverlapDeadline = &deadline
	h := newRotationHarness(now, &state)
	h.discoverer.targets = newTargets

	result, err := h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("Apply() during overlap = %v", err)
	}
	if result.State.Phase != PhasePublishingDualTrust || result.State.DesiredGeneration != 4 || result.State.PublishedGeneration != 3 {
		t.Fatalf("overlap restart state = %#v, want a new unpublished dual-trust generation", result.State)
	}
	if len(h.issuer.issues) != 0 || len(h.publisher.publications) != 0 || len(h.issuer.retired) != 0 {
		t.Fatalf("overlap target change issue=%d publish=%d retire=%d, want no candidate-only advancement", len(h.issuer.issues), len(h.publisher.publications), len(h.issuer.retired))
	}

	result, err = h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("Apply() issuing replacement dual trust = %v", err)
	}
	if result.State.Phase != PhaseAwaitingDualTrust || result.State.PublishedGeneration != 4 {
		t.Fatalf("replacement dual-trust state = %#v", result.State)
	}
	if len(h.issuer.issues) != 1 {
		t.Fatalf("issues = %#v, want exactly one replacement dual-trust issuance", h.issuer.issues)
	}
	issue := h.issuer.issues[0]
	if issue.Generation != 4 || !issue.DualTrust || issue.Signer.Fingerprint != state.Active.Fingerprint || !reflect.DeepEqual(issue.Targets, newTargets) {
		t.Fatalf("replacement issue = %#v, want active-signed dual trust for new targets %#v", issue, newTargets)
	}
}

func TestReconcilerRestartsDualTrustWhenTargetsChangeAfterCandidateOnlyPublication(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	state := testStableState(domain, now)
	candidate := Root{Fingerprint: "candidate-root", NotAfter: now.Add(domain.Policy.RootValidity)}
	oldTargets := []Target{{ID: "manager:old"}, {ID: "node:old"}}
	newTargets := []Target{{ID: "manager:new"}, {ID: "node:new"}}
	state.Phase = PhaseRetiringActiveRoot
	state.Candidate = &candidate
	state.OperationID = "candidate-only"
	state.DesiredGeneration = 4
	state.PublishedGeneration = 4
	state.PublishedDualTrust = false
	state.Targets = oldTargets
	h := newRotationHarness(now, &state)
	h.discoverer.targets = newTargets

	result, err := h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("Apply() after candidate-only target change = %v", err)
	}
	if result.State.Phase != PhasePublishingDualTrust || result.State.DesiredGeneration != 5 || result.State.PublishedGeneration != 4 {
		t.Fatalf("candidate-only restart state = %#v, want replacement dual-trust intent", result.State)
	}
	if len(h.issuer.issues) != 0 || len(h.publisher.publications) != 0 || len(h.issuer.retired) != 0 {
		t.Fatalf("candidate-only target change issue=%d publish=%d retire=%d, want no retirement advancement", len(h.issuer.issues), len(h.publisher.publications), len(h.issuer.retired))
	}

	result, err = h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("Apply() issuing replacement dual trust = %v", err)
	}
	if result.State.Phase != PhaseAwaitingDualTrust || result.State.PublishedGeneration != 5 {
		t.Fatalf("replacement dual-trust state = %#v", result.State)
	}
	issue := h.issuer.issues[0]
	if issue.Generation != 5 || !issue.DualTrust || issue.Signer.Fingerprint != state.Active.Fingerprint || !reflect.DeepEqual(issue.Targets, newTargets) {
		t.Fatalf("replacement issue = %#v, want active-signed dual trust for new targets %#v", issue, newTargets)
	}
}

func TestReconcilerBlocksWhenRequiredAcknowledgementIsMissing(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	state := testStableState(domain, now)
	candidate := Root{Fingerprint: "candidate-root", NotAfter: now.Add(domain.Policy.RootValidity)}
	state.Phase = PhaseAwaitingDualTrust
	state.Candidate = &candidate
	state.DesiredGeneration = 2
	state.PublishedGeneration = 2
	state.PublishedDualTrust = true
	state.PublishedMaterials = map[string]MaterialFingerprint{
		"default": {LeafFingerprint: "leaf-2", TrustFingerprint: "dual-trust"},
	}
	state.Targets = []Target{{ID: "manager"}, {ID: "zeistd/node-a"}}
	h := newRotationHarness(now, &state)
	h.discoverer.targets = cloneTargets(state.Targets)
	h.verifier.verify = func(_ VerificationRequest) ([]Acknowledgement, error) {
		return []Acknowledgement{{TargetID: "manager", Generation: 2}}, nil
	}

	result, err := h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.State.Phase != PhaseBlocked || !strings.Contains(result.State.BlockedReason, "lacks required acknowledgements") {
		t.Fatalf("state = %#v, want blocked missing-acknowledgement state", result.State)
	}
	if result.State.BlockedFrom != PhaseAwaitingDualTrust {
		t.Fatalf("blocked from = %q, want %q", result.State.BlockedFrom, PhaseAwaitingDualTrust)
	}
	if len(h.issuer.retired) != 0 || len(h.issuer.issues) != 0 || len(h.publisher.publications) != 0 {
		t.Fatalf("issuer retire=%d issue=%d publish=%d after incomplete acknowledgement, want no advancement", len(h.issuer.retired), len(h.issuer.issues), len(h.publisher.publications))
	}

	// A transient acknowledgement loss must not make the durable lifecycle
	// terminal. Retrying restores the exact prior verification phase, then
	// advances only after the same generation has complete evidence.
	h.verifier.verify = acknowledgementsForAllTargets
	result, err = h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("retry Apply() error = %v", err)
	}
	if result.State.Phase != PhaseActivatingCandidateLeaves || result.State.BlockedFrom != "" || result.State.BlockedReason != "" {
		t.Fatalf("retry state = %#v, want resumed dual-trust verification", result.State)
	}
	if len(h.issuer.retired) != 0 || len(h.issuer.issues) != 0 || len(h.publisher.publications) != 0 {
		t.Fatalf("issuer retire=%d issue=%d publish=%d after resumed verification, want no leaf activation yet", len(h.issuer.retired), len(h.issuer.issues), len(h.publisher.publications))
	}
}

func TestReconcilerResumesBlockedOrdinaryLeafVerification(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	state := testStableState(domain, now)
	state.Phase = PhaseAwaitingCandidateActivation
	state.DesiredGeneration = 2
	state.PublishedGeneration = 2
	state.PublishedMaterials = map[string]MaterialFingerprint{
		"default": {LeafFingerprint: "leaf-2", TrustFingerprint: "active-trust"},
	}
	state.Targets = []Target{{ID: "consumer"}}
	h := newRotationHarness(now, &state)
	h.discoverer.targets = cloneTargets(state.Targets)
	h.verifier.verify = func(_ VerificationRequest) ([]Acknowledgement, error) { return nil, nil }

	blocked, err := h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	if blocked.State.Phase != PhaseBlocked || blocked.State.BlockedFrom != PhaseAwaitingCandidateActivation {
		t.Fatalf("blocked ordinary renewal = %#v", blocked.State)
	}

	h.verifier.verify = acknowledgementsForAllTargets
	resumed, err := h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("resumed Apply() error = %v", err)
	}
	if resumed.State.Phase != PhaseStable || resumed.State.Candidate != nil || resumed.State.BlockedFrom != "" || resumed.State.BlockedReason != "" {
		t.Fatalf("resumed ordinary renewal = %#v, want stable state", resumed.State)
	}
}

func TestReconcilerBlocksAcknowledgementForWrongRoleMaterial(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	state := testStableState(domain, now)
	candidate := Root{Fingerprint: "candidate-root", NotAfter: now.Add(domain.Policy.RootValidity)}
	state.Phase = PhaseAwaitingDualTrust
	state.Candidate = &candidate
	state.DesiredGeneration = 2
	state.PublishedGeneration = 2
	state.PublishedDualTrust = true
	state.PublishedMaterials = map[string]MaterialFingerprint{
		"client": {LeafFingerprint: "client-leaf", TrustFingerprint: "shared-dual-trust"},
		"server": {LeafFingerprint: "server-leaf", TrustFingerprint: "shared-dual-trust"},
	}
	state.Targets = []Target{
		{ID: "manager", Evidence: map[string]string{"role": "client"}},
		{ID: "zeistd/node-a", Evidence: map[string]string{"role": "server"}},
	}
	h := newRotationHarness(now, &state)
	h.discoverer.targets = cloneTargets(state.Targets)
	h.verifier.verify = func(_ VerificationRequest) ([]Acknowledgement, error) {
		return []Acknowledgement{
			{TargetID: "manager", Generation: 2, LeafFingerprint: "client-leaf", TrustFingerprint: "shared-dual-trust"},
			// A target ID and generation alone are not sufficient evidence: the
			// daemon must prove it loaded its own server leaf, not the client leaf.
			{TargetID: "zeistd/node-a", Generation: 2, LeafFingerprint: "client-leaf", TrustFingerprint: "shared-dual-trust"},
		}, nil
	}

	result, err := h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.State.Phase != PhaseBlocked || !strings.Contains(result.State.BlockedReason, "lacks required acknowledgements") {
		t.Fatalf("state = %#v, want blocked role-material mismatch", result.State)
	}
}

func TestReconcilerReplaysPublishedButUnpersistedLeafGeneration(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	state := testStableState(domain, now)
	state.LeafNotAfter = now.Add(domain.Policy.LeafRenewBefore - time.Minute)
	state.Targets = []Target{{ID: "consumer"}}
	h := newRotationHarness(now, &state)
	// Save 1 persists the new desired generation. Save 2 simulates an
	// interruption after a successful public publication but before its state
	// was committed; a retry must reuse that generation and operation ID.
	h.store.failSave[2] = errors.New("simulated state-store interruption")

	if _, err := h.reconciler.Apply(context.Background(), h.domain); err == nil || !strings.Contains(err.Error(), "simulated state-store interruption") {
		t.Fatalf("first Apply() error = %v, want post-publication persistence failure", err)
	}
	if len(h.issuer.issues) != 1 || len(h.publisher.publications) != 1 {
		t.Fatalf("first attempt issue=%d publish=%d, want one each", len(h.issuer.issues), len(h.publisher.publications))
	}
	firstIssue := h.issuer.issues[0]

	result, err := h.reconciler.Apply(context.Background(), h.domain)
	if err != nil {
		t.Fatalf("retry Apply() error = %v", err)
	}
	if result.State.Phase != PhaseAwaitingCandidateActivation || result.State.PublishedGeneration != 2 {
		t.Fatalf("retry result = %#v, want replayed generation 2 awaiting proof", result.State)
	}
	if len(h.issuer.roots) != 0 || len(h.issuer.issues) != 2 || len(h.publisher.publications) != 2 {
		t.Fatalf("retry roots=%d issue=%d publish=%d, want no new root and one idempotent replay", len(h.issuer.roots), len(h.issuer.issues), len(h.publisher.publications))
	}
	secondIssue := h.issuer.issues[1]
	if secondIssue.Generation != firstIssue.Generation || secondIssue.OperationID != firstIssue.OperationID || secondIssue.Signer != firstIssue.Signer || secondIssue.DualTrust != firstIssue.DualTrust {
		t.Fatalf("replay issue = %#v, want same generation and operation as %#v", secondIssue, firstIssue)
	}
}

func TestReconcilerDoesNotPublishWhenGenerationIntentConflicts(t *testing.T) {
	now := time.Date(2043, time.March, 14, 15, 9, 26, 0, time.UTC)
	domain := testDomain()
	state := testStableState(domain, now)
	state.LeafNotAfter = now.Add(domain.Policy.LeafRenewBefore - time.Minute)
	h := newRotationHarness(now, &state)
	h.store.failSave[1] = ErrConflict

	_, err := h.reconciler.Apply(context.Background(), h.domain)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Apply() error = %v, want ErrConflict", err)
	}
	if len(h.issuer.issues) != 0 || len(h.publisher.publications) != 0 {
		t.Fatalf("issue=%d publish=%d after intent conflict, want no external issuance", len(h.issuer.issues), len(h.publisher.publications))
	}
}

func testDomain() Domain {
	return Domain{
		Name:              "test-domain",
		Profile:           ProfileMTLS,
		ConfigurationHash: "sha256:test-config",
		Policy: Policy{
			RootValidity:        100 * time.Hour,
			RootRolloverBefore:  20 * time.Hour,
			LeafValidity:        20 * time.Hour,
			LeafRenewBefore:     5 * time.Hour,
			MinimumTrustOverlap: 3 * time.Hour,
			ClockSkew:           5 * time.Minute,
		},
	}
}

func testStableState(domain Domain, now time.Time) State {
	return State{
		SchemaVersion:       StateSchemaVersion,
		ConfigurationHash:   domain.ConfigurationHash,
		Phase:               PhaseStable,
		OperationID:         "initial-operation",
		Active:              Root{Fingerprint: "active-root", NotAfter: now.Add(2 * domain.Policy.RootRolloverBefore)},
		LeafNotAfter:        now.Add(2 * domain.Policy.LeafRenewBefore),
		DesiredGeneration:   1,
		PublishedGeneration: 1,
		PublishedMaterials: map[string]MaterialFingerprint{
			"default": {LeafFingerprint: "active-leaf", TrustFingerprint: "active-trust"},
		},
	}
}

func ptrState(state State) *State { return &state }

func eventIndex(events []string, want string) int {
	for index, event := range events {
		if event == want {
			return index
		}
	}
	return -1
}

type rotationHarness struct {
	domain     Domain
	now        time.Time
	events     []string
	store      *memoryStateStore
	issuer     *recordingIssuer
	publisher  *recordingPublisher
	discoverer *recordingDiscoverer
	verifier   *recordingVerifier
	reconciler Reconciler
}

func newRotationHarness(now time.Time, state *State) *rotationHarness {
	h := &rotationHarness{domain: testDomain(), now: now}
	h.store = &memoryStateStore{state: cloneStatePtr(state), failSave: make(map[int]error), events: &h.events}
	h.issuer = &recordingIssuer{now: func() time.Time { return h.now }, events: &h.events}
	h.publisher = &recordingPublisher{failPublish: make(map[int]error), events: &h.events}
	h.discoverer = &recordingDiscoverer{targets: []Target{{ID: "consumer"}}, events: &h.events}
	h.verifier = &recordingVerifier{verify: acknowledgementsForAllTargets, events: &h.events}
	h.reconciler = Reconciler{
		Store:      h.store,
		Locker:     recordingLocker{events: &h.events},
		Publisher:  h.publisher,
		Discoverer: h.discoverer,
		Verifier:   h.verifier,
		Issuer:     h.issuer,
		Now:        func() time.Time { return h.now },
	}
	return h
}

type memoryStateStore struct {
	state    *State
	version  uint64
	saves    []State
	saveCall int
	failSave map[int]error
	events   *[]string
}

func (s *memoryStateStore) Load(_ context.Context, _ string) (VersionedState, error) {
	*s.events = append(*s.events, "store.load")
	if s.state == nil {
		return VersionedState{}, ErrStateNotFound
	}
	return VersionedState{State: cloneState(*s.state), Version: fmt.Sprintf("%d", s.version)}, nil
}

func (s *memoryStateStore) Save(_ context.Context, _ string, state State, version string) (VersionedState, error) {
	s.saveCall++
	*s.events = append(*s.events, fmt.Sprintf("store.save:%s:%d", state.Phase, state.DesiredGeneration))
	if err := s.failSave[s.saveCall]; err != nil {
		return VersionedState{}, err
	}
	if s.state == nil {
		if version != "" {
			return VersionedState{}, ErrConflict
		}
	} else if version != fmt.Sprintf("%d", s.version) {
		return VersionedState{}, ErrConflict
	}
	s.version++
	s.state = ptrState(cloneState(state))
	s.saves = append(s.saves, cloneState(state))
	return VersionedState{State: cloneState(state), Version: fmt.Sprintf("%d", s.version)}, nil
}

type recordingLocker struct{ events *[]string }

func (l recordingLocker) Acquire(_ context.Context, _ string) (Lock, error) {
	*l.events = append(*l.events, "lock.acquire")
	return recordingLock{events: l.events}, nil
}

type recordingLock struct{ events *[]string }

func (l recordingLock) Release(context.Context) error {
	*l.events = append(*l.events, "lock.release")
	return nil
}

type recordingIssuer struct {
	now     func() time.Time
	roots   []Root
	issues  []IssueRequest
	retired []Root
	events  *[]string
}

func (i *recordingIssuer) CreateRoot(_ context.Context, domain Domain) (Root, error) {
	root := Root{Fingerprint: fmt.Sprintf("issuer-root-%d", len(i.roots)+1), NotAfter: i.now().Add(domain.Policy.RootValidity)}
	i.roots = append(i.roots, root)
	*i.events = append(*i.events, "issuer.create-root")
	return root, nil
}

func (i *recordingIssuer) Issue(_ context.Context, request IssueRequest) (Publication, error) {
	i.issues = append(i.issues, request)
	*i.events = append(*i.events, fmt.Sprintf("issuer.issue:%d", request.Generation))
	return Publication{
		Materials: map[string]MaterialFingerprint{
			"default": {
				LeafFingerprint:  fmt.Sprintf("leaf:%s:%d", request.Signer.Fingerprint, request.Generation),
				TrustFingerprint: fmt.Sprintf("trust:%s:%t", request.Signer.Fingerprint, request.DualTrust),
			},
		},
		LeafNotAfter: i.now().Add(request.Domain.Policy.LeafValidity),
	}, nil
}

func (i *recordingIssuer) RetireRoot(_ context.Context, _ Domain, root Root) error {
	i.retired = append(i.retired, root)
	*i.events = append(*i.events, "issuer.retire-root")
	return nil
}

type recordingPublisher struct {
	publications []Publication
	publishCall  int
	failPublish  map[int]error
	events       *[]string
}

func (p *recordingPublisher) Publish(_ context.Context, publication Publication) error {
	p.publishCall++
	p.publications = append(p.publications, publication)
	*p.events = append(*p.events, fmt.Sprintf("publisher.publish:%d", publication.Generation))
	return p.failPublish[p.publishCall]
}

type recordingDiscoverer struct {
	targets []Target
	err     error
	calls   int
	events  *[]string
}

func (d *recordingDiscoverer) Discover(_ context.Context, _ Domain) ([]Target, error) {
	d.calls++
	*d.events = append(*d.events, "discoverer.discover")
	return cloneTargets(d.targets), d.err
}

type recordingVerifier struct {
	verify func(VerificationRequest) ([]Acknowledgement, error)
	calls  []VerificationRequest
	events *[]string
}

func (v *recordingVerifier) Verify(_ context.Context, request VerificationRequest) ([]Acknowledgement, error) {
	v.calls = append(v.calls, request)
	*v.events = append(*v.events, fmt.Sprintf("verifier.verify:%d", request.Generation))
	return v.verify(request)
}

func acknowledgementsForAllTargets(request VerificationRequest) ([]Acknowledgement, error) {
	acknowledgements := make([]Acknowledgement, 0, len(request.Targets))
	for _, target := range request.Targets {
		material, found := request.Publication.MaterialFor(target)
		if !found {
			return nil, fmt.Errorf("no material for target %q", target.ID)
		}
		acknowledgements = append(acknowledgements, Acknowledgement{
			TargetID:         target.ID,
			Generation:       request.Generation,
			LeafFingerprint:  material.LeafFingerprint,
			TrustFingerprint: material.TrustFingerprint,
		})
	}
	return acknowledgements, nil
}

func cloneStatePtr(state *State) *State {
	if state == nil {
		return nil
	}
	copy := cloneState(*state)
	return &copy
}

func cloneState(state State) State {
	copy := state
	if state.Candidate != nil {
		candidate := *state.Candidate
		copy.Candidate = &candidate
	}
	if state.MinimumOverlapDeadline != nil {
		deadline := *state.MinimumOverlapDeadline
		copy.MinimumOverlapDeadline = &deadline
	}
	copy.Targets = cloneTargets(state.Targets)
	copy.Acknowledgements = append([]Acknowledgement(nil), state.Acknowledgements...)
	copy.PublishedMaterials = cloneMaterials(state.PublishedMaterials)
	return copy
}

func cloneTargets(targets []Target) []Target {
	copy := make([]Target, len(targets))
	for index, target := range targets {
		copy[index] = target
		if target.Evidence != nil {
			copy[index].Evidence = make(map[string]string, len(target.Evidence))
			for key, value := range target.Evidence {
				copy[index].Evidence[key] = value
			}
		}
	}
	return copy
}
