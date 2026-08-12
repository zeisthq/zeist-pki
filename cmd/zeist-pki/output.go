package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/zeisthq/zeist-pki/rotation"
)

// The command output structs intentionally copy only operational metadata out
// of rotation.State. In particular, they never marshal adapter Opaque values,
// PEM, private keys, Secret data, or Kubernetes credentials.
type planOutput struct {
	Plans []rotation.Plan `json:"plans"`
}

type applyOutput struct {
	Results []reconciliationSummary `json:"results"`
}

type runOutput struct {
	At       time.Time               `json:"at"`
	Results  []reconciliationSummary `json:"results"`
	Failures []runFailure            `json:"failures,omitempty"`
}

// runFailure is deliberately credential-free. A reconciliation error may be
// supplied by an adapter that handled Secret or TLS data, so only the known
// configured domain and a fixed operational message cross the CLI boundary.
type runFailure struct {
	Domain  string `json:"domain,omitempty"`
	Message string `json:"message,omitempty"`
}

type statusOutput struct {
	Domains []domainStatus `json:"domains"`
}

type verifyOutput struct {
	Results []verificationSummary `json:"results"`
}

type recoverOutput struct {
	Results []reconciliationSummary `json:"results"`
}

type reconciliationSummary struct {
	Domain                   string                `json:"domain"`
	Phase                    rotation.Phase        `json:"phase"`
	OperationID              string                `json:"operationID"`
	ActiveRootFingerprint    string                `json:"activeRootFingerprint"`
	CandidateRootFingerprint string                `json:"candidateRootFingerprint,omitempty"`
	RootExpiresAt            time.Time             `json:"rootExpiresAt"`
	LeafExpiresAt            time.Time             `json:"leafExpiresAt,omitempty"`
	DesiredGeneration        uint64                `json:"desiredGeneration"`
	PublishedGeneration      uint64                `json:"publishedGeneration"`
	AcknowledgedGeneration   uint64                `json:"acknowledgedGeneration"`
	DualTrustPublished       bool                  `json:"dualTrustPublished"`
	BlockedReason            string                `json:"blockedReason,omitempty"`
	NextActions              []rotation.ActionKind `json:"nextActions"`
}

type domainStatus struct {
	Domain                   string                `json:"domain"`
	Initialized              bool                  `json:"initialized"`
	Health                   string                `json:"health"`
	Phase                    rotation.Phase        `json:"phase,omitempty"`
	OperationID              string                `json:"operationID,omitempty"`
	ActiveRootFingerprint    string                `json:"activeRootFingerprint,omitempty"`
	CandidateRootFingerprint string                `json:"candidateRootFingerprint,omitempty"`
	RootExpiresAt            time.Time             `json:"rootExpiresAt,omitempty"`
	LeafExpiresAt            time.Time             `json:"leafExpiresAt,omitempty"`
	DesiredGeneration        uint64                `json:"desiredGeneration,omitempty"`
	PublishedGeneration      uint64                `json:"publishedGeneration,omitempty"`
	AcknowledgedGeneration   uint64                `json:"acknowledgedGeneration,omitempty"`
	DualTrustPublished       bool                  `json:"dualTrustPublished"`
	TargetCount              int                   `json:"targetCount,omitempty"`
	AcknowledgementCount     int                   `json:"acknowledgementCount,omitempty"`
	BlockedReason            string                `json:"blockedReason,omitempty"`
	NextActions              []rotation.ActionKind `json:"nextActions"`
}

type verificationSummary struct {
	Domain           string `json:"domain"`
	Generation       uint64 `json:"generation"`
	Acknowledgements int    `json:"acknowledgements"`
	Verified         bool   `json:"verified"`
}

func summarizeResult(domain string, result rotation.Result) reconciliationSummary {
	state := result.State
	summary := reconciliationSummary{
		Domain:                 domain,
		Phase:                  state.Phase,
		OperationID:            state.OperationID,
		ActiveRootFingerprint:  state.Active.Fingerprint,
		RootExpiresAt:          state.Active.NotAfter,
		LeafExpiresAt:          state.LeafNotAfter,
		DesiredGeneration:      state.DesiredGeneration,
		PublishedGeneration:    state.PublishedGeneration,
		AcknowledgedGeneration: state.AcknowledgedGeneration,
		DualTrustPublished:     state.PublishedDualTrust,
		BlockedReason:          state.BlockedReason,
		NextActions:            result.Plan.Actions,
	}
	if state.Candidate != nil {
		summary.CandidateRootFingerprint = state.Candidate.Fingerprint
	}
	return summary
}

func summarizeStatus(domain string, state rotation.State, plan rotation.Plan) domainStatus {
	status := domainStatus{
		Domain:                 domain,
		Initialized:            true,
		Health:                 stateHealth(state),
		Phase:                  state.Phase,
		OperationID:            state.OperationID,
		ActiveRootFingerprint:  state.Active.Fingerprint,
		RootExpiresAt:          state.Active.NotAfter,
		LeafExpiresAt:          state.LeafNotAfter,
		DesiredGeneration:      state.DesiredGeneration,
		PublishedGeneration:    state.PublishedGeneration,
		AcknowledgedGeneration: state.AcknowledgedGeneration,
		DualTrustPublished:     state.PublishedDualTrust,
		TargetCount:            len(state.Targets),
		AcknowledgementCount:   len(state.Acknowledgements),
		BlockedReason:          state.BlockedReason,
		NextActions:            plan.Actions,
	}
	if state.Candidate != nil {
		status.CandidateRootFingerprint = state.Candidate.Fingerprint
	}
	return status
}

func stateHealth(state rotation.State) string {
	if state.Phase == rotation.PhaseBlocked {
		return "blocked"
	}
	now := time.Now().UTC()
	if !state.Active.NotAfter.After(now) || (!state.LeafNotAfter.IsZero() && !state.LeafNotAfter.After(now)) {
		return "expired"
	}
	if state.DesiredGeneration != state.PublishedGeneration || state.PublishedGeneration != state.AcknowledgedGeneration {
		return "pending"
	}
	return "healthy"
}

func writeCommandOutput(output io.Writer, format string, value any) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	case "text":
		return writeTextOutput(output, value)
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}

func writeTextOutput(output io.Writer, value any) error {
	switch outputValue := value.(type) {
	case planOutput:
		for _, plan := range outputValue.Plans {
			if _, err := fmt.Fprintf(output, "domain=%s phase=%s actions=%s%s\n", plan.Domain, plan.Phase, actionText(plan.Actions), blockedSuffix(plan.BlockedReason)); err != nil {
				return err
			}
		}
	case applyOutput:
		return writeReconciliationText(output, outputValue.Results)
	case runOutput:
		if _, err := fmt.Fprintf(output, "at=%s\n", outputValue.At.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
		for _, failure := range outputValue.Failures {
			if _, err := fmt.Fprintf(output, "status=retrying domain=%s failure=%q\n", failure.Domain, failure.Message); err != nil {
				return err
			}
		}
		return writeReconciliationText(output, outputValue.Results)
	case statusOutput:
		for _, status := range outputValue.Domains {
			if _, err := fmt.Fprintf(output, "domain=%s initialized=%t health=%s phase=%s rootExpiresAt=%s leafExpiresAt=%s desiredGeneration=%d publishedGeneration=%d acknowledgedGeneration=%d targets=%d acknowledgements=%d actions=%s%s\n",
				status.Domain, status.Initialized, status.Health, status.Phase, timeText(status.RootExpiresAt), timeText(status.LeafExpiresAt), status.DesiredGeneration, status.PublishedGeneration, status.AcknowledgedGeneration, status.TargetCount, status.AcknowledgementCount, actionText(status.NextActions), blockedSuffix(status.BlockedReason)); err != nil {
				return err
			}
		}
	case verifyOutput:
		for _, result := range outputValue.Results {
			if _, err := fmt.Fprintf(output, "domain=%s generation=%d acknowledgements=%d verified=%t\n", result.Domain, result.Generation, result.Acknowledgements, result.Verified); err != nil {
				return err
			}
		}
	case recoverOutput:
		return writeReconciliationText(output, outputValue.Results)
	default:
		return fmt.Errorf("unsupported command output %T", value)
	}
	return nil
}

func writeReconciliationText(output io.Writer, results []reconciliationSummary) error {
	for _, result := range results {
		if _, err := fmt.Fprintf(output, "domain=%s phase=%s desiredGeneration=%d publishedGeneration=%d acknowledgedGeneration=%d rootExpiresAt=%s leafExpiresAt=%s actions=%s%s\n",
			result.Domain, result.Phase, result.DesiredGeneration, result.PublishedGeneration, result.AcknowledgedGeneration, timeText(result.RootExpiresAt), timeText(result.LeafExpiresAt), actionText(result.NextActions), blockedSuffix(result.BlockedReason)); err != nil {
			return err
		}
	}
	return nil
}

func actionText(actions []rotation.ActionKind) string {
	if len(actions) == 0 {
		return "none"
	}
	values := make([]string, 0, len(actions))
	for _, action := range actions {
		values = append(values, string(action))
	}
	return strings.Join(values, ",")
}

func blockedSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return " blockedReason=" + fmt.Sprintf("%q", reason)
}

func timeText(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format(time.RFC3339)
}
