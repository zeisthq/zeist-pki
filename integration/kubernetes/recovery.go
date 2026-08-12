package kubernetes

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/zeisthq/zeist-pki/pki"
	"github.com/zeisthq/zeist-pki/rotation"
)

// Recoverer adopts verified surviving public material only with an explicit
// active-root fingerprint confirmation. Because the missing State Secret also
// means the active private key cannot be trusted as recoverable, it persists a
// new candidate root and schedules a safe dual-trust rollover.
type Recoverer struct {
	Client kubernetes.Interface
	Store  StateStore
	// Locker is the same per-domain fence used by normal reconciliation. A
	// recovery writes new issuer authority, so it must never race Apply or a
	// second operator recovery attempt.
	Locker rotation.Locker
	Issuer Issuer
	Names  Names
	Now    func() time.Time
}

func (r Recoverer) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r Recoverer) Recover(ctx context.Context, domain rotation.Domain, confirmedFingerprint string) (result rotation.Result, err error) {
	if err := domain.Validate(); err != nil {
		return rotation.Result{}, err
	}
	if r.Locker == nil {
		return rotation.Result{}, fmt.Errorf("recovery lock is required")
	}
	lock, err := r.Locker.Acquire(ctx, domain.Name)
	if err != nil {
		return rotation.Result{}, fmt.Errorf("acquire %q recovery lock: %w", domain.Name, err)
	}
	var contextLock rotation.ContextLock
	if candidate, ok := lock.(rotation.ContextLock); ok {
		contextLock = candidate
		ctx = contextLock.Context()
	}
	defer func() {
		_ = lock.Release(context.Background())
		if lockErr := recoveryLockError(domain.Name, contextLock); lockErr != nil {
			// A lease renewal can fail concurrently with an adapter call. Do not
			// report a successful recovery across an uncertain fence boundary:
			// the next bounded reconciliation will replay from durable state.
			result = rotation.Result{}
			err = lockErr
		}
	}()
	if lockErr := recoveryLockError(domain.Name, contextLock); lockErr != nil {
		return rotation.Result{}, lockErr
	}
	if domain.Name == "webhook" {
		if err := r.Names.validateWebhookCanary(); err != nil {
			return rotation.Result{}, err
		}
	}
	_, err = r.Store.Load(ctx, domain.Name)
	if lockErr := recoveryLockError(domain.Name, contextLock); lockErr != nil {
		return rotation.Result{}, lockErr
	}
	if err == nil {
		return rotation.Result{}, fmt.Errorf("state for %q exists; guarded recovery is only for missing state", domain.Name)
	}
	if err != rotation.ErrStateNotFound {
		return rotation.Result{}, fmt.Errorf("load %q state before recovery: %w", domain.Name, err)
	}
	active, generation, leafNotAfter, err := r.survivingDomain(ctx, domain, confirmedFingerprint)
	if lockErr := recoveryLockError(domain.Name, contextLock); lockErr != nil {
		return rotation.Result{}, lockErr
	}
	if err != nil {
		return rotation.Result{}, err
	}
	candidate, err := r.Issuer.CreateRoot(ctx, domain)
	if lockErr := recoveryLockError(domain.Name, contextLock); lockErr != nil {
		return rotation.Result{}, lockErr
	}
	if err != nil {
		return rotation.Result{}, fmt.Errorf("create %q recovery candidate: %w", domain.Name, err)
	}
	state := rotation.State{
		SchemaVersion: rotation.StateSchemaVersion, ConfigurationHash: domain.ConfigurationHash,
		Phase: rotation.PhasePublishingDualTrust, OperationID: recoveryOperationID(),
		Active: active, ActiveKeyUnavailable: true, Candidate: &candidate,
		LeafNotAfter: leafNotAfter, DesiredGeneration: generation + 1, PublishedGeneration: generation,
	}
	saved, err := r.Store.Save(ctx, domain.Name, state, "")
	if lockErr := recoveryLockError(domain.Name, contextLock); lockErr != nil {
		return rotation.Result{}, lockErr
	}
	if err != nil {
		return rotation.Result{}, fmt.Errorf("persist %q guarded recovery state: %w", domain.Name, err)
	}
	plan, err := rotation.PlanAt(domain, &saved.State, r.now())
	if err != nil {
		return rotation.Result{}, err
	}
	return rotation.Result{State: saved.State, Plan: plan}, nil
}

func recoveryLockError(domain string, lock rotation.ContextLock) error {
	if lock == nil {
		return nil
	}
	if err := lock.Err(); err != nil {
		return fmt.Errorf("recovery lock %q was lost: %w", domain, err)
	}
	return nil
}

func (r Recoverer) survivingDomain(ctx context.Context, domain rotation.Domain, confirmed string) (rotation.Root, uint64, time.Time, error) {
	now := r.now()
	switch domain.Name {
	case "webhook":
		secret, err := r.Client.CoreV1().Secrets(r.Names.Namespace).Get(ctx, r.Names.WebhookSecret, metav1.GetOptions{})
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("read webhook output: %w", err)
		}
		roots, err := r.webhookRoots(ctx)
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, err
		}
		if err := validateSurvivingTrustRoots(roots, now); err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("surviving webhook root is invalid: %w", err)
		}
		active, err := confirmedPublicRoot(roots, confirmed)
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, err
		}
		leaf, err := pki.ParseLeafPEM(secret.Data["tls.crt"], secret.Data["tls.key"])
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("parse webhook output: %w", err)
		}
		if err := pki.ValidateLeaf(leaf, roots, pki.ProfileWebhook, now); err != nil || leaf.Certificate.CheckSignatureFrom(active.certificate) != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("webhook output is not signed by the confirmed root")
		}
		if err := validateWebhookServiceCertificate(leaf.Certificate, r.Names.Namespace, r.Names.WebhookService); err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("validate webhook output identity: %w", err)
		}
		canaryRoots, hasCanaryTrust, err := r.webhookCanaryRootsOptional(ctx, roots)
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, err
		}
		if hasCanaryTrust {
			if err := validateSurvivingTrustRoots(canaryRoots, now); err != nil {
				return rotation.Root{}, 0, time.Time{}, fmt.Errorf("surviving webhook canary root is invalid: %w", err)
			}
		}
		primaryEvidence, err := recoveryOutputEvidence(secret, domain.Name, certificateFingerprint(leaf.Certificate), bundleFingerprint(roots))
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("validate webhook output fencing: %w", err)
		}
		leafNotAfter := leaf.Certificate.NotAfter
		var evidence []recoveryOutputFence
		evidence = append(evidence, primaryEvidence)
		canary, err := r.Client.CoreV1().Secrets(r.Names.Namespace).Get(ctx, r.Names.WebhookCanarySecret, metav1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("read webhook canary output: %w", err)
		}
		if err == nil && hasSecretMaterial(canary) {
			if !hasCanaryTrust {
				return rotation.Root{}, 0, time.Time{}, fmt.Errorf("webhook canary output survives but its configured trust bundle is empty")
			}
			canaryLeaf, parseErr := pki.ParseLeafPEM(canary.Data["tls.crt"], canary.Data["tls.key"])
			if parseErr != nil {
				return rotation.Root{}, 0, time.Time{}, fmt.Errorf("parse webhook canary output: %w", parseErr)
			}
			if validateErr := pki.ValidateLeaf(canaryLeaf, canaryRoots, pki.ProfileWebhook, now); validateErr != nil {
				return rotation.Root{}, 0, time.Time{}, fmt.Errorf("validate webhook canary output: %w", validateErr)
			}
			if validateErr := validateWebhookServiceCertificate(canaryLeaf.Certificate, r.Names.Namespace, r.Names.WebhookCanaryService); validateErr != nil {
				return rotation.Root{}, 0, time.Time{}, fmt.Errorf("validate webhook canary output identity: %w", validateErr)
			}
			canaryEvidence, evidenceErr := recoveryOutputEvidence(canary, domain.Name, certificateFingerprint(canaryLeaf.Certificate), bundleFingerprint(canaryRoots))
			if evidenceErr != nil {
				return rotation.Root{}, 0, time.Time{}, fmt.Errorf("validate webhook canary output fencing: %w", evidenceErr)
			}
			evidence = append(evidence, canaryEvidence)
			if canaryLeaf.Certificate.NotAfter.Before(leafNotAfter) {
				leafNotAfter = canaryLeaf.Certificate.NotAfter
			}
		} else if hasCanaryTrust {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("webhook canary trust survives but its output Secret is empty or absent")
		}
		generation, evidenceErr := consistentRecoveryEvidence(evidence...)
		if evidenceErr != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("webhook output fencing is inconsistent: %w", evidenceErr)
		}
		return active.root, generation, leafNotAfter, nil
	case "mtls":
		server, err := r.Client.CoreV1().Secrets(r.Names.Namespace).Get(ctx, r.Names.ServerSecret, metav1.GetOptions{})
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("read server output: %w", err)
		}
		client, err := r.Client.CoreV1().Secrets(r.Names.Namespace).Get(ctx, r.Names.ClientSecret, metav1.GetOptions{})
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("read client output: %w", err)
		}
		serverRoots, err := pki.ParseCertificatesPEM(server.Data["ca.crt"])
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("parse server trust bundle: %w", err)
		}
		clientRoots, err := pki.ParseCertificatesPEM(client.Data["ca.crt"])
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("parse client trust bundle: %w", err)
		}
		if err := validateSurvivingTrustRoots(serverRoots, now); err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("surviving server trust root is invalid: %w", err)
		}
		if err := validateSurvivingTrustRoots(clientRoots, now); err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("surviving client trust root is invalid: %w", err)
		}
		if bundleFingerprint(serverRoots) != bundleFingerprint(clientRoots) {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("server and client surviving trust bundles differ")
		}
		active, err := confirmedPublicRoot(serverRoots, confirmed)
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, err
		}
		serverLeaf, err := pki.ParseLeafPEM(server.Data["tls.crt"], server.Data["tls.key"])
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("parse server output: %w", err)
		}
		clientLeaf, err := pki.ParseLeafPEM(client.Data["tls.crt"], client.Data["tls.key"])
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("parse client output: %w", err)
		}
		if err := pki.ValidateLeaf(serverLeaf, serverRoots, pki.ProfileServer, now); err != nil || serverLeaf.Certificate.CheckSignatureFrom(active.certificate) != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("server output is not signed by the confirmed root")
		}
		if err := pki.ValidateLeaf(clientLeaf, serverRoots, pki.ProfileClient, now); err != nil || clientLeaf.Certificate.CheckSignatureFrom(active.certificate) != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("client output is not signed by the confirmed root")
		}
		trustFingerprint := bundleFingerprint(serverRoots)
		serverEvidence, err := recoveryOutputEvidence(server, domain.Name, certificateFingerprint(serverLeaf.Certificate), trustFingerprint)
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("validate server output fencing: %w", err)
		}
		clientEvidence, err := recoveryOutputEvidence(client, domain.Name, certificateFingerprint(clientLeaf.Certificate), trustFingerprint)
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("validate client output fencing: %w", err)
		}
		generation, err := consistentRecoveryEvidence(serverEvidence, clientEvidence)
		if err != nil {
			return rotation.Root{}, 0, time.Time{}, fmt.Errorf("mTLS output fencing is inconsistent: %w", err)
		}
		leafNotAfter := serverLeaf.Certificate.NotAfter
		if clientLeaf.Certificate.NotAfter.Before(leafNotAfter) {
			leafNotAfter = clientLeaf.Certificate.NotAfter
		}
		return active.root, generation, leafNotAfter, nil
	default:
		return rotation.Root{}, 0, time.Time{}, fmt.Errorf("unsupported domain %q", domain.Name)
	}
}

// validateSurvivingTrustRoots rejects any root that would make recovery adopt
// an ambiguous or unsafe trust bundle. Unlike leaf validation, which can
// legitimately find one valid issuing root and ignore unrelated certificates,
// guarded recovery must fail closed when any surviving root is malformed or
// no longer valid.
func validateSurvivingTrustRoots(roots []*x509.Certificate, at time.Time) error {
	now := at.UTC().Truncate(time.Second)
	for _, root := range roots {
		if err := validatePublicRoot(root); err != nil {
			return err
		}
		if now.Before(root.NotBefore) || !now.Before(root.NotAfter) {
			return fmt.Errorf("root certificate is not currently valid")
		}
	}
	return nil
}

type publicRoot struct {
	root        rotation.Root
	certificate *x509.Certificate
}

func confirmedPublicRoot(roots []*x509.Certificate, confirmed string) (publicRoot, error) {
	if confirmed == "" {
		return publicRoot{}, fmt.Errorf("confirmed active-root fingerprint is required")
	}
	for _, certificate := range roots {
		if certificateFingerprint(certificate) != confirmed {
			continue
		}
		if err := validatePublicRoot(certificate); err != nil {
			return publicRoot{}, fmt.Errorf("confirmed root is invalid: %w", err)
		}
		return publicRoot{root: rotation.Root{Fingerprint: confirmed, NotAfter: certificate.NotAfter, Opaque: &rootAuthority{certificate: certificate}}, certificate: certificate}, nil
	}
	return publicRoot{}, fmt.Errorf("confirmed active-root fingerprint does not match surviving trust material")
}

func (r Recoverer) webhookRoots(ctx context.Context) ([]*x509.Certificate, error) {
	if len(r.Names.WebhookConfigurationNames) == 0 {
		return nil, fmt.Errorf("at least one named production webhook configuration is required")
	}
	var bundles [][]byte
	for _, name := range r.Names.WebhookConfigurationNames {
		configuredBundles, err := r.namedWebhookBundles(ctx, name, r.Names.WebhookService)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, configuredBundles...)
	}
	if len(bundles) == 0 {
		return nil, fmt.Errorf("no surviving webhook trust bundle references Service %s/%s", r.Names.Namespace, r.Names.WebhookService)
	}
	var roots []*x509.Certificate
	var expected string
	for _, bundle := range bundles {
		parsed, err := pki.ParseCertificatesPEM(bundle)
		if err != nil {
			return nil, fmt.Errorf("parse surviving webhook trust bundle: %w", err)
		}
		fingerprint := bundleFingerprint(parsed)
		if expected == "" {
			expected, roots = fingerprint, parsed
			continue
		}
		if expected != fingerprint {
			return nil, fmt.Errorf("surviving webhook configurations disagree on trust bundle")
		}
	}
	for _, root := range roots {
		if err := validatePublicRoot(root); err != nil {
			return nil, fmt.Errorf("surviving webhook root is invalid: %w", err)
		}
	}
	return roots, nil
}

// webhookCanaryRoots validates the separate candidate-only admission trust
// bundle. It intentionally does not demand equality with the production
// bundle: during dual trust it must contain exactly the candidate root, while
// the production endpoint continues to trust both roots.
func (r Recoverer) webhookCanaryRoots(ctx context.Context, productionRoots []*x509.Certificate) ([]*x509.Certificate, error) {
	roots, present, err := r.webhookCanaryRootsOptional(ctx, productionRoots)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, fmt.Errorf("webhook canary configuration %q has an empty trust bundle", r.Names.WebhookCanaryConfiguration)
	}
	return roots, nil
}

// webhookCanaryRootsOptional distinguishes an intentional legacy transition
// placeholder (empty configured caBundle and no candidate leaf yet) from
// malformed surviving candidate material. The configured VWC must always
// exist and reference the named canary Service; only its empty bundle is
// accepted before guarded recovery has persisted a new candidate root.
func (r Recoverer) webhookCanaryRootsOptional(ctx context.Context, productionRoots []*x509.Certificate) ([]*x509.Certificate, bool, error) {
	bundles, err := r.namedWebhookBundles(ctx, r.Names.WebhookCanaryConfiguration, r.Names.WebhookCanaryService)
	if err != nil {
		return nil, false, err
	}
	if len(bundles) == 0 {
		return nil, false, fmt.Errorf("webhook canary configuration %q does not reference the configured Service", r.Names.WebhookCanaryConfiguration)
	}
	empty := 0
	for _, bundle := range bundles {
		if len(bundle) == 0 {
			empty++
		}
	}
	if empty == len(bundles) {
		return nil, false, nil
	}
	if empty != 0 {
		return nil, false, fmt.Errorf("surviving webhook canary entries mix empty and populated trust bundles")
	}
	var roots []*x509.Certificate
	var expected string
	for _, bundle := range bundles {
		parsed, parseErr := pki.ParseCertificatesPEM(bundle)
		if parseErr != nil {
			return nil, false, fmt.Errorf("parse surviving webhook canary trust bundle: %w", parseErr)
		}
		if len(parsed) != 1 {
			return nil, false, fmt.Errorf("webhook canary trust bundle must contain exactly one root")
		}
		fingerprint := bundleFingerprint(parsed)
		if expected == "" {
			expected, roots = fingerprint, parsed
			continue
		}
		if expected != fingerprint {
			return nil, false, fmt.Errorf("surviving webhook canary entries disagree on trust bundle")
		}
	}
	if err := validatePublicRoot(roots[0]); err != nil {
		return nil, false, fmt.Errorf("surviving webhook canary root is invalid: %w", err)
	}
	found := false
	for _, root := range productionRoots {
		if certificateFingerprint(root) == certificateFingerprint(roots[0]) {
			found = true
			break
		}
	}
	if !found {
		return nil, false, fmt.Errorf("webhook canary root is absent from surviving production trust")
	}
	return roots, true, nil
}

func (r Recoverer) namedWebhookBundles(ctx context.Context, name, service string) ([][]byte, error) {
	var bundles [][]byte
	configuration, err := r.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		bundles = append(bundles, matchingMutatingBundles(configuration, r.Names.Namespace, service)...)
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("read mutating webhook trust %q: %w", name, err)
	}
	configurationV, err := r.Client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		bundles = append(bundles, matchingValidatingBundles(configurationV, r.Names.Namespace, service)...)
		return bundles, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("read configured webhook trust %q: %w", name, err)
	}
	return bundles, nil
}

func matchingMutatingBundles(configuration *admissionv1.MutatingWebhookConfiguration, namespace, service string) [][]byte {
	var bundles [][]byte
	for _, webhook := range configuration.Webhooks {
		if webhookServiceMatches(webhook.ClientConfig.Service, namespace, service) {
			bundles = append(bundles, webhook.ClientConfig.CABundle)
		}
	}
	return bundles
}

func matchingValidatingBundles(configuration *admissionv1.ValidatingWebhookConfiguration, namespace, service string) [][]byte {
	var bundles [][]byte
	for _, webhook := range configuration.Webhooks {
		if webhookServiceMatches(webhook.ClientConfig.Service, namespace, service) {
			bundles = append(bundles, webhook.ClientConfig.CABundle)
		}
	}
	return bundles
}

// recoveryOutputEvidence validates the operation fence of a surviving output.
// Fully unannotated legacy material is accepted only as an all-output migration
// set; a partial or malformed fence is ambiguous evidence and must rebootstrap
// under operator control instead of being silently adopted.
type recoveryOutputFence struct {
	managed    bool
	generation uint64
	operation  string
}

func recoveryOutputEvidence(secret *corev1.Secret, domain, leafFingerprint, trustFingerprint string) (recoveryOutputFence, error) {
	if secret == nil {
		return recoveryOutputFence{}, fmt.Errorf("output Secret is required")
	}
	annotations := secret.Annotations
	values := []string{
		annotations[annotationDomain], annotations[annotationGeneration], annotations[annotationOperation],
		annotations[annotationLeafFingerprint], annotations[annotationTrustFingerprint],
	}
	present := 0
	for _, value := range values {
		if value != "" {
			present++
		}
	}
	if present == 0 {
		return recoveryOutputFence{}, nil
	}
	if present != len(values) {
		return recoveryOutputFence{}, fmt.Errorf("Secret %s has partial managed annotations", secret.Name)
	}
	if annotations[annotationDomain] != domain {
		return recoveryOutputFence{}, fmt.Errorf("Secret %s belongs to domain %q", secret.Name, annotations[annotationDomain])
	}
	generation, err := strconv.ParseUint(annotations[annotationGeneration], 10, 64)
	if err != nil || generation == 0 || annotations[annotationGeneration] != fmt.Sprintf("%d", generation) {
		return recoveryOutputFence{}, fmt.Errorf("Secret %s has an invalid publication generation", secret.Name)
	}
	if annotations[annotationLeafFingerprint] != leafFingerprint || annotations[annotationTrustFingerprint] != trustFingerprint {
		return recoveryOutputFence{}, fmt.Errorf("Secret %s annotations do not match its published material", secret.Name)
	}
	return recoveryOutputFence{managed: true, generation: generation, operation: annotations[annotationOperation]}, nil
}

func consistentRecoveryEvidence(outputs ...recoveryOutputFence) (uint64, error) {
	if len(outputs) == 0 {
		return 0, fmt.Errorf("no surviving output evidence")
	}
	managed := outputs[0].managed
	for _, output := range outputs[1:] {
		if output.managed != managed {
			return 0, fmt.Errorf("managed and legacy outputs are mixed")
		}
	}
	if !managed {
		return 1, nil
	}
	first := outputs[0]
	for _, output := range outputs[1:] {
		if output.generation != first.generation || output.operation != first.operation {
			return 0, fmt.Errorf("output generations or operation identities disagree")
		}
	}
	return first.generation, nil
}

func recoveryOperationID() string {
	var data [16]byte
	if _, err := cryptorand.Read(data[:]); err == nil {
		return "recover-" + hex.EncodeToString(data[:])
	}
	return fmt.Sprintf("recover-%d", time.Now().UnixNano())
}
