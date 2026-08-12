// Package rotation provides the portable, replay-safe state machine used to
// operate a small number of private PKI trust domains.
package rotation

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const StateSchemaVersion = "pki.zeist.io/v1alpha1"

var (
	// ErrStateNotFound reports that no authoritative state has been persisted.
	ErrStateNotFound = errors.New("rotation state not found")
	// ErrConflict reports an optimistic-lock conflict while persisting state.
	ErrConflict = errors.New("rotation state conflict")
)

// Phase is one durable root-rotation phase. Every phase is safe to replay.
type Phase string

const (
	PhaseStable                      Phase = "Stable"
	PhasePublishingDualTrust         Phase = "PublishingDualTrust"
	PhaseAwaitingDualTrust           Phase = "AwaitingDualTrust"
	PhaseActivatingCandidateLeaves   Phase = "ActivatingCandidateLeaves"
	PhaseAwaitingCandidateActivation Phase = "AwaitingCandidateActivation"
	PhaseOverlap                     Phase = "Overlap"
	PhaseRetiringActiveRoot          Phase = "RetiringActiveRoot"
	PhaseBlocked                     Phase = "Blocked"
)

// Profile selects one of the intentionally small built-in certificate sets.
type Profile string

const (
	ProfileWebhook Profile = "webhook"
	ProfileMTLS    Profile = "mtls"
)

// Policy controls expiration and the overlap required to retire a trust root.
type Policy struct {
	RootValidity        time.Duration `json:"rootValidity" yaml:"rootValidity"`
	RootRolloverBefore  time.Duration `json:"rootRolloverBefore" yaml:"rootRolloverBefore"`
	LeafValidity        time.Duration `json:"leafValidity" yaml:"leafValidity"`
	LeafRenewBefore     time.Duration `json:"leafRenewBefore" yaml:"leafRenewBefore"`
	MinimumTrustOverlap time.Duration `json:"minimumTrustOverlap" yaml:"minimumTrustOverlap"`
	ClockSkew           time.Duration `json:"clockSkew" yaml:"clockSkew"`
}

// DefaultPolicy returns the safe v0.1 lifecycle policy.
func DefaultPolicy() Policy {
	return Policy{
		RootValidity:        365 * 24 * time.Hour,
		RootRolloverBefore:  90 * 24 * time.Hour,
		LeafValidity:        90 * 24 * time.Hour,
		LeafRenewBefore:     30 * 24 * time.Hour,
		MinimumTrustOverlap: 30 * 24 * time.Hour,
		ClockSkew:           5 * time.Minute,
	}
}

// Validate ensures a policy can produce a safe lifecycle.
func (p Policy) Validate() error {
	if p.RootValidity <= 0 || p.RootRolloverBefore <= 0 || p.LeafValidity <= 0 ||
		p.LeafRenewBefore <= 0 || p.MinimumTrustOverlap <= 0 || p.ClockSkew < 0 {
		return fmt.Errorf("all rotation durations must be positive except clock skew")
	}
	if p.RootRolloverBefore >= p.RootValidity {
		return fmt.Errorf("root rollover boundary must be before root expiry")
	}
	if p.LeafRenewBefore >= p.LeafValidity {
		return fmt.Errorf("leaf renewal boundary must be before leaf expiry")
	}
	if p.LeafValidity+p.ClockSkew > p.RootValidity-p.RootRolloverBefore {
		return fmt.Errorf("leaf validity cannot exceed remaining root lifetime at rollover boundary")
	}
	return nil
}

// Domain configures one independently managed trust domain.
type Domain struct {
	Name              string            `json:"name" yaml:"name"`
	Profile           Profile           `json:"profile" yaml:"profile"`
	ConfigurationHash string            `json:"configurationHash" yaml:"-"`
	Policy            Policy            `json:"policy" yaml:"policy"`
	Metadata          map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// Validate checks a domain before any state or key material is created.
func (d Domain) Validate() error {
	if d.Name == "" {
		return fmt.Errorf("domain name is required")
	}
	if d.Profile != ProfileWebhook && d.Profile != ProfileMTLS {
		return fmt.Errorf("domain %q has unsupported profile %q", d.Name, d.Profile)
	}
	if d.ConfigurationHash == "" {
		return fmt.Errorf("domain %q configuration hash is required", d.Name)
	}
	return d.Policy.Validate()
}

// Root identifies a root without storing private material in public state.
type Root struct {
	Fingerprint string    `json:"fingerprint" yaml:"fingerprint"`
	NotAfter    time.Time `json:"notAfter" yaml:"notAfter"`
	// Opaque is adapter-owned private authority for this root. It is deliberately
	// excluded from serialized State: a StateStore keeps it in its restricted
	// authority location and restores it when loading State. The engine never
	// needs to understand its concrete type.
	Opaque any `json:"-" yaml:"-"`
}

// Target is an exact consumer that must acknowledge a published generation.
type Target struct {
	ID       string            `json:"id" yaml:"id"`
	Evidence map[string]string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

// Acknowledgement proves a target observed an exact published generation.
type Acknowledgement struct {
	TargetID         string    `json:"targetID" yaml:"targetID"`
	Generation       uint64    `json:"generation" yaml:"generation"`
	LeafFingerprint  string    `json:"leafFingerprint" yaml:"leafFingerprint"`
	TrustFingerprint string    `json:"trustFingerprint" yaml:"trustFingerprint"`
	ObservedAt       time.Time `json:"observedAt" yaml:"observedAt"`
}

// MaterialFingerprint identifies the exact leaf and trust bundle used by one
// consumer role within a published generation. An mTLS domain normally has
// distinct client and server leaf fingerprints while sharing its trust bundle.
type MaterialFingerprint struct {
	LeafFingerprint  string `json:"leafFingerprint" yaml:"leafFingerprint"`
	TrustFingerprint string `json:"trustFingerprint" yaml:"trustFingerprint"`
}

// State persists only references and evidence, never application credentials
// or duplicated PEM. Integrations keep root private keys in their restricted
// state store alongside this value.
type State struct {
	SchemaVersion     string `json:"schemaVersion" yaml:"schemaVersion"`
	ConfigurationHash string `json:"configurationHash" yaml:"configurationHash"`
	Phase             Phase  `json:"phase" yaml:"phase"`
	OperationID       string `json:"operationID" yaml:"operationID"`
	Active            Root   `json:"active" yaml:"active"`
	// ActiveKeyUnavailable is set only by guarded recovery when the confirmed
	// active root certificate survives but its private key does not. It forces a
	// dual-trust rollover that preserves existing leaves until candidate trust
	// is proven; it must never be inferred silently.
	ActiveKeyUnavailable   bool                           `json:"activeKeyUnavailable" yaml:"activeKeyUnavailable"`
	Candidate              *Root                          `json:"candidate,omitempty" yaml:"candidate,omitempty"`
	LeafNotAfter           time.Time                      `json:"leafNotAfter,omitempty" yaml:"leafNotAfter,omitempty"`
	DesiredGeneration      uint64                         `json:"desiredGeneration" yaml:"desiredGeneration"`
	PublishedGeneration    uint64                         `json:"publishedGeneration" yaml:"publishedGeneration"`
	PublishedMaterials     map[string]MaterialFingerprint `json:"publishedMaterials,omitempty" yaml:"publishedMaterials,omitempty"`
	PublishedDualTrust     bool                           `json:"publishedDualTrust" yaml:"publishedDualTrust"`
	AcknowledgedGeneration uint64                         `json:"acknowledgedGeneration" yaml:"acknowledgedGeneration"`
	Targets                []Target                       `json:"targets,omitempty" yaml:"targets,omitempty"`
	Acknowledgements       []Acknowledgement              `json:"acknowledgements,omitempty" yaml:"acknowledgements,omitempty"`
	MinimumOverlapDeadline *time.Time                     `json:"minimumOverlapDeadline,omitempty" yaml:"minimumOverlapDeadline,omitempty"`
	// RetirementAuthorized is durable intent to delete the old active root. It
	// is written only after candidate-only trust has been proven, and before the
	// Issuer is asked to retire the old authority. This makes that destructive
	// operation replay-safe after a process crash.
	RetirementAuthorized bool `json:"retirementAuthorized" yaml:"retirementAuthorized"`
	// BlockedFrom records the retry-safe phase that observed a transient
	// verification or discovery failure. It is empty for an operator-action
	// block caused by structurally inconsistent state. A later Apply retries
	// only a non-empty, verification-safe origin; it never skips to a later
	// rotation phase merely because time elapsed.
	BlockedFrom   Phase  `json:"blockedFrom,omitempty" yaml:"blockedFrom,omitempty"`
	BlockedReason string `json:"blockedReason,omitempty" yaml:"blockedReason,omitempty"`
}

// VersionedState supports an optimistic-locking persistence adapter.
type VersionedState struct {
	State   State
	Version string
}

// StateStore owns authoritative state. An implementation must return
// ErrStateNotFound when state does not exist and ErrConflict when Version does
// not match its current persistence version.
type StateStore interface {
	Load(context.Context, string) (VersionedState, error)
	Save(context.Context, string, State, string) (VersionedState, error)
}

// Lock is a per-domain concurrent-reconciliation fence.
type Lock interface {
	Release(context.Context) error
}

// ContextLock is an optional renewable-fence extension for lock adapters that
// can detect ownership loss while a bounded reconciliation is still running.
// The returned Context is cancelled as soon as the fence is lost so all later
// adapter effects receive cancellation. Err reports that ownership-loss cause;
// it is nil for ordinary caller cancellation and successful release.
//
// The base Lock interface stays intentionally small so non-Kubernetes
// embedders do not need a heartbeat implementation. Reconciler uses this
// interface when an adapter supplies it.
type ContextLock interface {
	Lock
	Context() context.Context
	Err() error
}

// Locker obtains a bounded per-domain fence. It must never be held across the
// configured trust-overlap duration.
type Locker interface {
	Acquire(context.Context, string) (Lock, error)
}

// Publication is the complete public material for one generation. Private
// root keys never appear here.
type Publication struct {
	Domain      string
	Generation  uint64
	OperationID string
	// Materials maps a target role (for example webhook, client, or server)
	// to the exact active leaf and trust bundle fingerprints. It contains no
	// PEM, private key, or other credential material.
	Materials    map[string]MaterialFingerprint
	LeafNotAfter time.Time
	DualTrust    bool
	// AdoptExisting is set only for the guarded lost-active-key recovery path.
	// It authorizes an integration to replace the trust bundle and fencing
	// annotations while retaining the already validated leaf/key pair. Routine
	// publication must never adopt an operation-fenced older output.
	AdoptExisting bool
	// Opaque carries transient adapter-owned output material between Issue and
	// Publish. It is never serialized into State or returned by status output.
	// A replaying Issuer reconstructs it from its restricted store or an already
	// published, operation-fenced output.
	Opaque any `json:"-" yaml:"-"`
}

// MaterialFor returns the exact evidence expected from one target. Targets
// without a role are supported for single-role domains only.
func (p Publication) MaterialFor(target Target) (MaterialFingerprint, bool) {
	if target.Evidence != nil && target.Evidence["role"] != "" {
		material, found := p.Materials[target.Evidence["role"]]
		return material, found
	}
	if len(p.Materials) != 1 {
		return MaterialFingerprint{}, false
	}
	for _, material := range p.Materials {
		return material, true
	}
	return MaterialFingerprint{}, false
}

// Publisher distributes a complete public generation atomically at its own
// boundary. A successful write is distribution, not consumer acknowledgement.
type Publisher interface {
	Publish(context.Context, Publication) error
}

// Discoverer returns the current exact target snapshot for a domain.
type Discoverer interface {
	Discover(context.Context, Domain) ([]Target, error)
}

// VerificationRequest is an exact evidence request for one published
// generation and target snapshot.
type VerificationRequest struct {
	Domain      Domain
	Generation  uint64
	OperationID string
	Targets     []Target
	Publication Publication
}

// Verifier proves that target consumers loaded and actively use a generation.
type Verifier interface {
	Verify(context.Context, VerificationRequest) ([]Acknowledgement, error)
}

// Issuer performs private-key operations. The key store behind it is adapter
// owned and must keep issuer material separate from consumer outputs.
type Issuer interface {
	CreateRoot(context.Context, Domain) (Root, error)
	Issue(context.Context, IssueRequest) (Publication, error)
	RetireRoot(context.Context, Domain, Root) error
}

// BootstrapGuard is optionally implemented by an issuer adapter that can
// determine whether public outputs survive without authoritative state. It
// lets the portable reconciler fail closed instead of silently minting a new
// root into an adopted or partially lost deployment.
type BootstrapGuard interface {
	GuardBootstrap(context.Context, Domain) error
}

// IssueRequest gives issuer adapters the stable operation identity required to
// make an interrupted publish replay the same leaf generation.
type IssueRequest struct {
	Domain Domain
	Signer Root
	// Candidate identifies the candidate authority during a dual-trust root
	// rollover. It is separate from TrustRoots because their canonical ordering
	// is deliberately fingerprint-based. An integration may use it for a
	// candidate-only activation probe without guessing phase identity from the
	// signing root.
	Candidate *Root
	// TrustRoots is the public trust bundle to distribute. Signer is the root
	// that signs this generation; during dual trust this normally also contains
	// the candidate root.
	TrustRoots []Root
	// Targets is the durable discovery snapshot persisted before issuance. It
	// supplies endpoint/SAN inputs without making the portable engine depend on
	// a particular discovery system.
	Targets []Target
	// ReuseExistingLeaves permits the explicit lost-key recovery path to retain
	// validated active-signed leaves while publishing a dual trust bundle. It is
	// never used for routine issuance or renewal.
	ReuseExistingLeaves bool
	DualTrust           bool
	Generation          uint64
	OperationID         string
}
