package rotation

import (
	"fmt"
	"time"
)

// ActionKind is an observable next step. Planning performs no external work.
type ActionKind string

const (
	ActionBootstrapRoot     ActionKind = "BootstrapRoot"
	ActionRenewLeaves       ActionKind = "RenewLeaves"
	ActionBeginRootRollover ActionKind = "BeginRootRollover"
	ActionPublishDualTrust  ActionKind = "PublishDualTrust"
	ActionVerifyDualTrust   ActionKind = "VerifyDualTrust"
	ActionActivateCandidate ActionKind = "ActivateCandidateLeaves"
	ActionVerifyCandidate   ActionKind = "VerifyCandidateActivation"
	ActionMaintainOverlap   ActionKind = "MaintainOverlap"
	ActionRetireActiveRoot  ActionKind = "RetireActiveRoot"
	ActionVerifyRetirement  ActionKind = "VerifyRetirement"
	ActionBlocked           ActionKind = "Blocked"
)

// Plan is a deterministic preview of a reconciliation outcome.
type Plan struct {
	Domain        string       `json:"domain" yaml:"domain"`
	Phase         Phase        `json:"phase" yaml:"phase"`
	Actions       []ActionKind `json:"actions" yaml:"actions"`
	BlockedReason string       `json:"blockedReason,omitempty" yaml:"blockedReason,omitempty"`
}

// PlanAt determines the action sequence without generating material or
// writing state. A nil state means fresh bootstrap.
func PlanAt(domain Domain, state *State, now time.Time) (Plan, error) {
	if err := domain.Validate(); err != nil {
		return Plan{}, err
	}
	if state == nil {
		return Plan{Domain: domain.Name, Phase: PhaseStable, Actions: []ActionKind{ActionBootstrapRoot, ActionRenewLeaves}}, nil
	}
	if err := validateState(domain, *state); err != nil {
		return Plan{}, err
	}
	result := Plan{Domain: domain.Name, Phase: state.Phase}
	switch state.Phase {
	case PhaseStable:
		if state.DesiredGeneration > state.PublishedGeneration {
			result.Actions = []ActionKind{ActionRenewLeaves}
			return result, nil
		}
		if !now.Add(domain.Policy.RootRolloverBefore).Add(domain.Policy.ClockSkew).Before(state.Active.NotAfter) {
			result.Actions = []ActionKind{ActionBeginRootRollover, ActionPublishDualTrust}
			return result, nil
		}
		if state.LeafNotAfter.IsZero() || !now.Add(domain.Policy.LeafRenewBefore).Add(domain.Policy.ClockSkew).Before(state.LeafNotAfter) {
			result.Actions = []ActionKind{ActionRenewLeaves}
			return result, nil
		}
	case PhasePublishingDualTrust:
		result.Actions = []ActionKind{ActionPublishDualTrust}
	case PhaseAwaitingDualTrust:
		result.Actions = []ActionKind{ActionVerifyDualTrust}
	case PhaseActivatingCandidateLeaves:
		result.Actions = []ActionKind{ActionActivateCandidate}
	case PhaseAwaitingCandidateActivation:
		result.Actions = []ActionKind{ActionVerifyCandidate}
	case PhaseOverlap:
		if state.MinimumOverlapDeadline == nil {
			return Plan{}, fmt.Errorf("overlap state has no minimum-overlap deadline")
		}
		if now.Before(*state.MinimumOverlapDeadline) {
			result.Actions = []ActionKind{ActionMaintainOverlap}
		} else {
			result.Actions = []ActionKind{ActionRetireActiveRoot}
		}
	case PhaseRetiringActiveRoot:
		result.Actions = []ActionKind{ActionRetireActiveRoot, ActionVerifyRetirement}
	case PhaseBlocked:
		result.Actions = []ActionKind{ActionBlocked}
		result.BlockedReason = state.BlockedReason
	default:
		return Plan{}, fmt.Errorf("unknown rotation phase %q", state.Phase)
	}
	return result, nil
}

func validateState(domain Domain, state State) error {
	if state.SchemaVersion != StateSchemaVersion {
		return fmt.Errorf("unsupported state schema %q", state.SchemaVersion)
	}
	if state.ConfigurationHash != domain.ConfigurationHash {
		return fmt.Errorf("state configuration hash does not match domain %q", domain.Name)
	}
	if state.Active.Fingerprint == "" || state.Active.NotAfter.IsZero() {
		return fmt.Errorf("state has no valid active root")
	}
	if state.Phase != PhaseStable && state.Phase != PhaseBlocked && state.Phase != PhaseAwaitingCandidateActivation && state.Candidate == nil {
		return fmt.Errorf("phase %q requires a candidate root", state.Phase)
	}
	if state.Phase == PhaseBlocked && state.BlockedFrom != "" {
		if !retryableBlockedPhase(state.BlockedFrom) {
			return fmt.Errorf("blocked state has unsupported retry phase %q", state.BlockedFrom)
		}
		if state.BlockedFrom != PhaseAwaitingCandidateActivation && state.Candidate == nil {
			return fmt.Errorf("blocked retry phase %q requires a candidate root", state.BlockedFrom)
		}
	}
	if state.Candidate != nil && (state.Candidate.Fingerprint == "" || state.Candidate.NotAfter.IsZero()) {
		return fmt.Errorf("state candidate root is invalid")
	}
	if len(state.Targets) != 0 {
		if err := validateTargetSnapshot(state.Targets); err != nil {
			return fmt.Errorf("state has invalid target snapshot: %w", err)
		}
	}
	return nil
}
