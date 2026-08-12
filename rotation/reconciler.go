package rotation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Reconciler performs one idempotent, bounded domain reconciliation.
type Reconciler struct {
	Store      StateStore
	Locker     Locker
	Publisher  Publisher
	Discoverer Discoverer
	Verifier   Verifier
	Issuer     Issuer
	Now        func() time.Time
}

// Result describes the durable phase after a reconciliation attempt.
type Result struct {
	State State
	Plan  Plan
}

// Apply acquires the domain lock, persists intent before every external
// operation, and advances at most one durable lifecycle phase. External
// adapters must make Issue and Publish idempotent by operation ID.
func (r Reconciler) Apply(ctx context.Context, domain Domain) (result Result, err error) {
	if err := r.validate(); err != nil {
		return Result{}, err
	}
	if err := domain.Validate(); err != nil {
		return Result{}, err
	}
	lock, err := r.Locker.Acquire(ctx, domain.Name)
	if err != nil {
		return Result{}, fmt.Errorf("acquire %q rotation lock: %w", domain.Name, err)
	}
	var contextLock ContextLock
	if candidate, ok := lock.(ContextLock); ok {
		contextLock = candidate
		ctx = contextLock.Context()
	}
	defer func() {
		_ = lock.Release(context.Background())
		if contextLock != nil {
			if lockErr := contextLock.Err(); lockErr != nil {
				// A renewal failure can race a returned adapter result. Prefer the
				// fence failure so the caller retries a fully replay-safe operation
				// rather than treating an uncertain ownership boundary as success.
				result = Result{}
				err = fmt.Errorf("rotation lock %q was lost: %w", domain.Name, lockErr)
			}
		}
	}()
	if contextLock != nil {
		if lockErr := contextLock.Err(); lockErr != nil {
			return Result{}, fmt.Errorf("rotation lock %q was lost: %w", domain.Name, lockErr)
		}
	}

	loaded, err := r.Store.Load(ctx, domain.Name)
	if err != nil && err != ErrStateNotFound {
		return Result{}, fmt.Errorf("load %q state: %w", domain.Name, err)
	}
	if err == ErrStateNotFound {
		return r.bootstrap(ctx, domain)
	}
	plan, err := PlanAt(domain, &loaded.State, r.now())
	if err != nil {
		return Result{}, err
	}
	state := loaded.State
	switch state.Phase {
	case PhaseStable:
		// A root rollover is higher priority than a routine endpoint or leaf
		// change: the later dual-trust publication will capture the current
		// target snapshot under the candidate rollover operation.
		if contains(plan.Actions, ActionBeginRootRollover) {
			return r.beginRollover(ctx, domain, loaded)
		}
		changed, err := r.targetsChanged(ctx, domain, state.Targets)
		if err != nil {
			return Result{}, fmt.Errorf("discover %q current targets: %w", domain.Name, err)
		}
		if changed {
			return r.issueLeaves(ctx, domain, loaded, state.Active, false, PhaseAwaitingCandidateActivation)
		}
		if contains(plan.Actions, ActionRenewLeaves) {
			return r.issueLeaves(ctx, domain, loaded, state.Active, false, PhaseAwaitingCandidateActivation)
		}
		return Result{State: state, Plan: plan}, nil
	case PhasePublishingDualTrust:
		// Establish consumer dual trust while keeping the active-signed leaf in
		// service. Candidate-signed leaves are activated only after that trust
		// has been observed by every selected consumer.
		signer := state.Active
		if state.ActiveKeyUnavailable {
			// Guarded recovery has a confirmed old public root but no old private
			// key. The issuer reuses validated existing leaves and only expands
			// their trust bundle; candidate-signed leaves still wait for proof.
			signer = *state.Candidate
		}
		return r.issueLeaves(ctx, domain, loaded, signer, true, PhaseAwaitingDualTrust)
	case PhaseAwaitingDualTrust:
		return r.verify(ctx, domain, loaded, PhaseActivatingCandidateLeaves)
	case PhaseActivatingCandidateLeaves:
		// The dual-trust proof is scoped to the persisted target snapshot. Do
		// not issue a candidate-signed leaf to a target that appeared after that
		// proof; restart from active-signed dual trust instead.
		changed, err := r.targetsChanged(ctx, domain, state.Targets)
		if err != nil {
			// Match ordinary issuance discovery behavior: no external effect has
			// occurred in this phase yet, so return a retryable reconciliation
			// error without durably converting a transient API failure into a
			// terminal blocked state.
			return Result{}, fmt.Errorf("discover candidate activation targets: %w", err)
		}
		if changed {
			return r.restartRolloverForTargets(ctx, domain, loaded)
		}
		return r.issueLeaves(ctx, domain, loaded, *state.Candidate, true, PhaseAwaitingCandidateActivation)
	case PhaseAwaitingCandidateActivation:
		next := PhaseStable
		if state.Candidate != nil {
			next = PhaseOverlap
		}
		return r.verify(ctx, domain, loaded, next)
	case PhaseOverlap:
		return r.overlap(ctx, domain, loaded, plan)
	case PhaseRetiringActiveRoot:
		return r.retire(ctx, domain, loaded)
	case PhaseBlocked:
		return r.resumeBlocked(ctx, domain, loaded)
	default:
		return Result{}, fmt.Errorf("unsupported phase %q", state.Phase)
	}
}

func (r Reconciler) bootstrap(ctx context.Context, domain Domain) (Result, error) {
	if guard, ok := r.Issuer.(BootstrapGuard); ok {
		if err := guard.GuardBootstrap(ctx, domain); err != nil {
			return Result{}, fmt.Errorf("guard %q bootstrap: %w", domain.Name, err)
		}
	}
	root, err := r.Issuer.CreateRoot(ctx, domain)
	if err != nil {
		return Result{}, fmt.Errorf("create %q root: %w", domain.Name, err)
	}
	state := State{
		SchemaVersion:     StateSchemaVersion,
		ConfigurationHash: domain.ConfigurationHash,
		Phase:             PhaseStable,
		OperationID:       newOperationID(),
		Active:            root,
		DesiredGeneration: 1,
	}
	// Persist root authority before any public leaf material is issued.
	saved, err := r.Store.Save(ctx, domain.Name, state, "")
	if err != nil {
		return Result{}, fmt.Errorf("persist %q bootstrap state: %w", domain.Name, err)
	}
	return r.issueLeaves(ctx, domain, saved, root, false, PhaseAwaitingCandidateActivation)
}

func (r Reconciler) beginRollover(ctx context.Context, domain Domain, loaded VersionedState) (Result, error) {
	candidate, err := r.Issuer.CreateRoot(ctx, domain)
	if err != nil {
		return Result{}, fmt.Errorf("create %q candidate root: %w", domain.Name, err)
	}
	state := loaded.State
	state.Candidate = &candidate
	state.Phase = PhasePublishingDualTrust
	state.OperationID = newOperationID()
	state.DesiredGeneration++
	state.Acknowledgements = nil
	state.Targets = nil
	state.MinimumOverlapDeadline = nil
	return r.persist(ctx, domain, VersionedState{State: state, Version: loaded.Version})
}

func (r Reconciler) issueLeaves(
	ctx context.Context,
	domain Domain,
	loaded VersionedState,
	signer Root,
	dualTrust bool,
	next Phase,
) (Result, error) {
	state := loaded.State
	targets, err := r.Discoverer.Discover(ctx, domain)
	if err != nil {
		return Result{}, fmt.Errorf("discover %q issuance targets: %w", domain.Name, err)
	}
	if err := validateTargetSnapshot(targets); err != nil {
		return Result{}, fmt.Errorf("discover %q issuance targets: %w", domain.Name, err)
	}
	if state.DesiredGeneration == state.PublishedGeneration {
		state.DesiredGeneration++
		state.OperationID = newOperationID()
		state.Acknowledgements = nil
	}
	// The discovery snapshot is authoritative for this generation. Persist it
	// before leaf issuance or publication so a crash cannot silently broaden a
	// generation's SAN set or acknowledgement quorum on replay.
	if !targetsEqual(state.Targets, targets) || loaded.State.DesiredGeneration != state.DesiredGeneration {
		state.Targets = copyTargets(targets)
		state.Acknowledgements = nil
		saved, err := r.Store.Save(ctx, domain.Name, state, loaded.Version)
		if err != nil {
			return Result{}, fmt.Errorf("persist %q publication intent: %w", domain.Name, err)
		}
		loaded = saved
	}
	return r.publish(ctx, domain, loaded, signer, dualTrust, next)
}

func (r Reconciler) publish(
	ctx context.Context,
	domain Domain,
	loaded VersionedState,
	signer Root,
	dualTrust bool,
	next Phase,
) (Result, error) {
	state := loaded.State
	publication, err := r.Issuer.Issue(ctx, IssueRequest{
		Domain: domain, Signer: signer, Candidate: state.Candidate, TrustRoots: r.trustRoots(state, signer, dualTrust), Targets: copyTargets(state.Targets), DualTrust: dualTrust,
		Generation: state.DesiredGeneration, OperationID: state.OperationID,
		ReuseExistingLeaves: state.ActiveKeyUnavailable && dualTrust && state.Candidate != nil && signer.Fingerprint == state.Candidate.Fingerprint,
	})
	if err != nil {
		return Result{}, fmt.Errorf("issue %q generation %d: %w", domain.Name, state.DesiredGeneration, err)
	}
	if len(publication.Materials) == 0 || publication.LeafNotAfter.IsZero() {
		return Result{}, fmt.Errorf("issue %q generation %d returned incomplete publication", domain.Name, state.DesiredGeneration)
	}
	for role, material := range publication.Materials {
		if role == "" || material.LeafFingerprint == "" || material.TrustFingerprint == "" {
			return Result{}, fmt.Errorf("issue %q generation %d returned incomplete %q material", domain.Name, state.DesiredGeneration, role)
		}
	}
	publication.Domain = domain.Name
	publication.Generation = state.DesiredGeneration
	publication.OperationID = state.OperationID
	publication.DualTrust = dualTrust
	publication.AdoptExisting = state.ActiveKeyUnavailable && dualTrust && state.Candidate != nil && signer.Fingerprint == state.Candidate.Fingerprint
	if err := r.Publisher.Publish(ctx, publication); err != nil {
		return Result{}, fmt.Errorf("publish %q generation %d: %w", domain.Name, publication.Generation, err)
	}
	state.PublishedGeneration = publication.Generation
	state.PublishedMaterials = cloneMaterials(publication.Materials)
	state.PublishedDualTrust = publication.DualTrust
	state.LeafNotAfter = publication.LeafNotAfter
	state.Phase = next
	state.Acknowledgements = nil
	return r.persist(ctx, domain, VersionedState{State: state, Version: loaded.Version})
}

func (r Reconciler) verify(ctx context.Context, domain Domain, loaded VersionedState, next Phase) (Result, error) {
	state := loaded.State
	if state.PublishedGeneration != state.DesiredGeneration || state.PublishedGeneration == 0 {
		return r.blockTerminal(ctx, domain, loaded, "published generation does not match desired generation")
	}
	currentTargets, err := r.Discoverer.Discover(ctx, domain)
	if err != nil {
		return r.block(ctx, domain, loaded, fmt.Sprintf("discover current targets: %v", err))
	}
	if !targetsEqual(state.Targets, currentTargets) {
		state.Targets = copyTargets(currentTargets)
		state.DesiredGeneration++
		state.OperationID = newOperationID()
		state.Acknowledgements = nil
		state.PublishedGeneration = 0
		state.PublishedMaterials = nil
		state.PublishedDualTrust = false
		switch state.Phase {
		case PhaseAwaitingDualTrust:
			state.Phase = PhasePublishingDualTrust
		case PhaseAwaitingCandidateActivation:
			if state.Candidate != nil {
				// A candidate leaf is already active for the old snapshot. A
				// newly selected consumer must first prove the active-signed
				// dual-trust generation; candidate activation cannot be reused
				// across a target-set change.
				state.Phase = PhasePublishingDualTrust
			} else {
				state.Phase = PhaseStable
			}
		}
		return r.persist(ctx, domain, VersionedState{State: state, Version: loaded.Version})
	}
	publication := Publication{
		Domain: domain.Name, Generation: state.PublishedGeneration, OperationID: state.OperationID,
		Materials: cloneMaterials(state.PublishedMaterials), LeafNotAfter: state.LeafNotAfter, DualTrust: state.PublishedDualTrust,
	}
	acknowledgements, err := r.Verifier.Verify(ctx, VerificationRequest{
		Domain: domain, Generation: state.PublishedGeneration, OperationID: state.OperationID,
		Targets: state.Targets, Publication: publication,
	})
	if err != nil {
		return r.block(ctx, domain, loaded, fmt.Sprintf("verify generation %d: %v", state.PublishedGeneration, err))
	}
	if !acknowledgesAll(state.Targets, acknowledgements, publication) {
		return r.block(ctx, domain, loaded, fmt.Sprintf("generation %d lacks required acknowledgements", state.PublishedGeneration))
	}
	state.Acknowledgements = acknowledgements
	state.AcknowledgedGeneration = state.PublishedGeneration
	state.BlockedFrom = ""
	state.BlockedReason = ""
	state.Phase = next
	if next == PhaseOverlap {
		deadline := r.now().Add(domain.Policy.MinimumTrustOverlap)
		state.MinimumOverlapDeadline = &deadline
	}
	return r.persist(ctx, domain, VersionedState{State: state, Version: loaded.Version})
}

func (r Reconciler) retire(ctx context.Context, domain Domain, loaded VersionedState) (Result, error) {
	state := loaded.State
	if state.Candidate == nil {
		return r.blockTerminal(ctx, domain, loaded, "retirement has no candidate root")
	}
	currentTargets, err := r.Discoverer.Discover(ctx, domain)
	if err != nil {
		return r.block(ctx, domain, loaded, fmt.Sprintf("discover retirement targets: %v", err))
	}
	if !targetsEqual(state.Targets, currentTargets) {
		return r.restartRolloverForTargets(ctx, domain, loaded)
	}
	if state.PublishedGeneration != state.DesiredGeneration {
		// The exact target snapshot was dual-trust verified before this
		// candidate-only intent was persisted. Do not rediscover targets in
		// issueLeaves here: a newly appeared consumer has not proven dual trust
		// and requires an entire safe rollover cycle instead.
		return r.publish(ctx, domain, loaded, *state.Candidate, false, PhaseRetiringActiveRoot)
	}
	if state.PublishedDualTrust {
		return r.blockTerminal(ctx, domain, loaded, "retirement has no candidate-only publication")
	}
	publication := Publication{
		Domain: domain.Name, Generation: state.PublishedGeneration, OperationID: state.OperationID,
		Materials: cloneMaterials(state.PublishedMaterials), LeafNotAfter: state.LeafNotAfter, DualTrust: false,
	}
	acknowledgements, err := r.Verifier.Verify(ctx, VerificationRequest{
		Domain: domain, Generation: state.PublishedGeneration, OperationID: state.OperationID,
		Targets: state.Targets, Publication: publication,
	})
	if err != nil {
		return r.block(ctx, domain, loaded, fmt.Sprintf("verify retirement generation: %v", err))
	}
	if !acknowledgesAll(state.Targets, acknowledgements, publication) {
		return r.block(ctx, domain, loaded, "candidate-only trust lacks required acknowledgements")
	}
	if !state.RetirementAuthorized {
		state.Acknowledgements = acknowledgements
		state.AcknowledgedGeneration = state.PublishedGeneration
		state.RetirementAuthorized = true
		// The successful candidate-only verification is the first point at
		// which a transient blocked reason may be cleared. Persist destructive
		// authorization separately so a crash never deletes the old root before
		// that proof is durable.
		state.BlockedFrom = ""
		state.BlockedReason = ""
		return r.persist(ctx, domain, VersionedState{State: state, Version: loaded.Version})
	}
	retired := state.Active
	state.Active = *state.Candidate
	state.ActiveKeyUnavailable = false
	state.Candidate = nil
	state.Phase = PhaseStable
	state.Acknowledgements = acknowledgements
	state.AcknowledgedGeneration = state.PublishedGeneration
	state.MinimumOverlapDeadline = nil
	state.RetirementAuthorized = false
	state.BlockedFrom = ""
	state.BlockedReason = ""
	// Store the trust switch (and, for integrations that keep it there, old key
	// deletion) before invoking any optional external cleanup. A restart after
	// this point is safe: the old root is no longer trusted or authoritative.
	result, err := r.persist(ctx, domain, VersionedState{State: state, Version: loaded.Version})
	if err != nil {
		return Result{}, err
	}
	if err := r.Issuer.RetireRoot(ctx, domain, retired); err != nil {
		return result, fmt.Errorf("retire inactive root after persisted trust switch: %w", err)
	}
	return result, nil
}

// overlap holds both roots live until the required time boundary, while still
// watching the selected consumer snapshot. A new consumer may only enter a
// rollover through a fresh dual-trust and activation-proof sequence; it must
// never inherit a candidate-only publication merely because it appeared after
// the original snapshot was acknowledged.
func (r Reconciler) overlap(ctx context.Context, domain Domain, loaded VersionedState, plan Plan) (Result, error) {
	state := loaded.State
	if state.MinimumOverlapDeadline == nil {
		return r.blockTerminal(ctx, domain, loaded, "overlap phase has no deadline")
	}
	currentTargets, err := r.Discoverer.Discover(ctx, domain)
	if err != nil {
		return r.block(ctx, domain, loaded, fmt.Sprintf("discover overlap targets: %v", err))
	}
	if !targetsEqual(state.Targets, currentTargets) {
		return r.restartRolloverForTargets(ctx, domain, loaded)
	}
	if r.now().Before(*state.MinimumOverlapDeadline) {
		return Result{State: state, Plan: plan}, nil
	}
	// Persist candidate-only intent against the already dual-trust-proven
	// target snapshot. Retire verifies the snapshot again immediately before it
	// issues, and restarts from dual trust if it has changed in the meantime.
	state.Phase = PhaseRetiringActiveRoot
	state.OperationID = newOperationID()
	state.DesiredGeneration++
	state.Acknowledgements = nil
	state.RetirementAuthorized = false
	return r.persist(ctx, domain, VersionedState{State: state, Version: loaded.Version})
}

// restartRolloverForTargets invalidates all later rollover proof when the
// selected target snapshot changes. It deliberately retains the last
// published material as the truthful current output while persisting a new
// dual-trust operation intent. The next bounded reconciliation snapshots the
// new targets before issuing an active-signed (or explicit recovery) dual
// trust generation.
func (r Reconciler) restartRolloverForTargets(ctx context.Context, domain Domain, loaded VersionedState) (Result, error) {
	state := loaded.State
	if state.Candidate == nil {
		return r.blockTerminal(ctx, domain, loaded, "target change has no candidate root to restart rollover")
	}
	state.Phase = PhasePublishingDualTrust
	state.OperationID = newOperationID()
	state.DesiredGeneration++
	state.Acknowledgements = nil
	state.MinimumOverlapDeadline = nil
	state.RetirementAuthorized = false
	state.BlockedFrom = ""
	state.BlockedReason = ""
	return r.persist(ctx, domain, VersionedState{State: state, Version: loaded.Version})
}

func (r Reconciler) targetsChanged(ctx context.Context, domain Domain, previous []Target) (bool, error) {
	targets, err := r.Discoverer.Discover(ctx, domain)
	if err != nil {
		return false, err
	}
	if err := validateTargetSnapshot(targets); err != nil {
		return false, err
	}
	return !targetsEqual(previous, targets), nil
}

func (r Reconciler) trustRoots(state State, signer Root, dualTrust bool) []Root {
	if !dualTrust || state.Candidate == nil {
		return []Root{signer}
	}
	// Stable ordering makes trust-bundle content deterministic regardless of
	// which root signed the leaf for the current rollover phase.
	roots := []Root{state.Active, *state.Candidate}
	if roots[0].Fingerprint > roots[1].Fingerprint {
		roots[0], roots[1] = roots[1], roots[0]
	}
	return roots
}

func (r Reconciler) block(ctx context.Context, domain Domain, loaded VersionedState, reason string) (Result, error) {
	state := loaded.State
	if retryableBlockedPhase(state.Phase) {
		state.BlockedFrom = state.Phase
	}
	state.Phase = PhaseBlocked
	state.BlockedReason = reason
	return r.persist(ctx, domain, VersionedState{State: state, Version: loaded.Version})
}

// blockTerminal retains no retry origin for state that is structurally unsafe
// to re-enter. Unlike a missing acknowledgement or transient discovery error,
// a missing candidate or incomplete publication intent cannot become safe just
// by trying the same phase again.
func (r Reconciler) blockTerminal(ctx context.Context, domain Domain, loaded VersionedState, reason string) (Result, error) {
	state := loaded.State
	state.Phase = PhaseBlocked
	state.BlockedFrom = ""
	state.BlockedReason = reason
	return r.persist(ctx, domain, VersionedState{State: state, Version: loaded.Version})
}

// resumeBlocked retries only the verification-safe phase that actually
// observed the transient failure. It persists the restored phase before the
// retry so a process crash cannot turn a failed acknowledgement into implicit
// progress. BlockedReason remains visible until a real verification succeeds.
func (r Reconciler) resumeBlocked(ctx context.Context, domain Domain, loaded VersionedState) (Result, error) {
	state := loaded.State
	if !retryableBlockedPhase(state.BlockedFrom) {
		plan, err := PlanAt(domain, &state, r.now())
		if err != nil {
			return Result{}, err
		}
		return Result{State: state, Plan: plan}, nil
	}
	state.Phase = state.BlockedFrom
	saved, err := r.Store.Save(ctx, domain.Name, state, loaded.Version)
	if err != nil {
		return Result{}, fmt.Errorf("persist %q blocked retry intent: %w", domain.Name, err)
	}
	switch saved.State.Phase {
	case PhaseAwaitingDualTrust:
		return r.verify(ctx, domain, saved, PhaseActivatingCandidateLeaves)
	case PhaseAwaitingCandidateActivation:
		next := PhaseStable
		if saved.State.Candidate != nil {
			next = PhaseOverlap
		}
		return r.verify(ctx, domain, saved, next)
	case PhaseRetiringActiveRoot:
		return r.retire(ctx, domain, saved)
	case PhaseOverlap:
		plan, err := PlanAt(domain, &saved.State, r.now())
		if err != nil {
			return Result{}, err
		}
		return r.overlap(ctx, domain, saved, plan)
	default:
		return Result{}, fmt.Errorf("blocked retry phase %q is not supported", saved.State.Phase)
	}
}

func retryableBlockedPhase(phase Phase) bool {
	switch phase {
	case PhaseAwaitingDualTrust, PhaseAwaitingCandidateActivation, PhaseOverlap, PhaseRetiringActiveRoot:
		return true
	default:
		return false
	}
}

func (r Reconciler) persist(ctx context.Context, domain Domain, loaded VersionedState) (Result, error) {
	saved, err := r.Store.Save(ctx, domain.Name, loaded.State, loaded.Version)
	if err != nil {
		return Result{}, fmt.Errorf("persist %q state: %w", domain.Name, err)
	}
	plan, err := PlanAt(domain, &saved.State, r.now())
	if err != nil {
		return Result{}, err
	}
	return Result{State: saved.State, Plan: plan}, nil
}

func (r Reconciler) validate() error {
	if r.Store == nil || r.Locker == nil || r.Publisher == nil || r.Discoverer == nil || r.Verifier == nil || r.Issuer == nil {
		return fmt.Errorf("store, locker, publisher, discoverer, verifier, and issuer are required")
	}
	return nil
}

func (r Reconciler) now() time.Time {
	if r.Now == nil {
		return time.Now().UTC()
	}
	return r.Now().UTC()
}

func contains(actions []ActionKind, want ActionKind) bool {
	for _, action := range actions {
		if action == want {
			return true
		}
	}
	return false
}

func acknowledgesAll(targets []Target, acknowledgements []Acknowledgement, publication Publication) bool {
	if len(targets) == 0 {
		return false
	}
	seen := make(map[string]Acknowledgement, len(acknowledgements))
	for _, acknowledgement := range acknowledgements {
		if acknowledgement.Generation == publication.Generation && acknowledgement.TargetID != "" {
			seen[acknowledgement.TargetID] = acknowledgement
		}
	}
	targetIDs := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if target.ID == "" {
			return false
		}
		if _, duplicate := targetIDs[target.ID]; duplicate {
			return false
		}
		targetIDs[target.ID] = struct{}{}
		acknowledgement, found := seen[target.ID]
		material, materialFound := publication.MaterialFor(target)
		if !found || !materialFound || acknowledgement.LeafFingerprint != material.LeafFingerprint || acknowledgement.TrustFingerprint != material.TrustFingerprint {
			return false
		}
	}
	return true
}

func cloneMaterials(materials map[string]MaterialFingerprint) map[string]MaterialFingerprint {
	if len(materials) == 0 {
		return nil
	}
	clone := make(map[string]MaterialFingerprint, len(materials))
	for role, material := range materials {
		clone[role] = material
	}
	return clone
}

func copyTargets(targets []Target) []Target {
	if len(targets) == 0 {
		return nil
	}
	clone := make([]Target, len(targets))
	for index, target := range targets {
		clone[index] = target
		if target.Evidence != nil {
			clone[index].Evidence = make(map[string]string, len(target.Evidence))
			for key, value := range target.Evidence {
				clone[index].Evidence[key] = value
			}
		}
	}
	return clone
}

func targetsEqual(first, second []Target) bool {
	if len(first) != len(second) {
		return false
	}
	byID := make(map[string]Target, len(first))
	for _, target := range first {
		if target.ID == "" {
			return false
		}
		if _, duplicate := byID[target.ID]; duplicate {
			return false
		}
		byID[target.ID] = target
	}
	secondIDs := make(map[string]struct{}, len(second))
	for _, target := range second {
		if target.ID == "" {
			return false
		}
		if _, duplicate := secondIDs[target.ID]; duplicate {
			return false
		}
		secondIDs[target.ID] = struct{}{}
		expected, found := byID[target.ID]
		if !found || len(expected.Evidence) != len(target.Evidence) {
			return false
		}
		for key, value := range expected.Evidence {
			if target.Evidence[key] != value {
				return false
			}
		}
	}
	return true
}

// validateTargetSnapshot makes the acknowledgement quorum unambiguous before
// a discovered snapshot is persisted or used for issuance. A portable
// Discoverer may be custom, so the core must not assume Kubernetes-style
// uniqueness.
func validateTargetSnapshot(targets []Target) error {
	if len(targets) == 0 {
		return fmt.Errorf("no targets")
	}
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if target.ID == "" {
			return fmt.Errorf("target ID is required")
		}
		if _, duplicate := seen[target.ID]; duplicate {
			return fmt.Errorf("duplicate target ID %q", target.ID)
		}
		seen[target.ID] = struct{}{}
	}
	return nil
}

func newOperationID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		// crypto/rand failure is system-fatal for issuance; this fallback only
		// preserves a non-empty correlation ID for a system-level fault path.
		return fmt.Sprintf("rotation-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes[:])
}
