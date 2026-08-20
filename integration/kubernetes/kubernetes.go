// Package kubernetes supplies the Kubernetes persistence, fencing, discovery,
// publication, and verification primitives used by the zeist-pki CLI. It is
// intentionally an adapter around the portable rotation package, not a CRD or
// controller framework.
package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	contractv1 "github.com/zeisthq/zeist-pki/contract/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/zeisthq/zeist-pki/rotation"
)

const (
	StateSecretPrefix = "zeist-"
	StateSecretSuffix = "-pki-state"
	stateDataKey      = "state.json"
	activeCAKey       = "active-ca.crt"
	activeCAKeyKey    = "active-ca.key"
	candidateCAKey    = "candidate-ca.crt"
	candidateCAKeyKey = "candidate-ca.key"

	annotationDomain           = contractv1.DomainAnnotation
	annotationGeneration       = contractv1.GenerationAnnotation
	annotationOperation        = contractv1.OperationAnnotation
	annotationLeafFingerprint  = contractv1.LeafFingerprintAnnotation
	annotationTrustFingerprint = contractv1.TrustFingerprintAnnotation
)

// Names defines the fixed Zeist v0.1 outputs owned by one integration.
type Names struct {
	Namespace                  string
	AcknowledgementNamespace   string
	WebhookSecret              string
	WebhookCanarySecret        string
	ServerSecret               string
	ClientSecret               string
	WebhookService             string
	WebhookCanaryService       string
	WebhookCanaryConfiguration string
	WebhookCanaryResourcePath  string
	WebhookCanaryAnnotation    string
	// APIServerEndpoints is an optional explicit HA control-plane endpoint
	// set. When supplied, the webhook canary must reach every HTTPS origin.
	// An empty set uses the active client-go API-server endpoint.
	APIServerEndpoints        []string
	WebhookConfigurationNames []string
	RunnerService             string
	WebhookPodSelector        string
	ManagerPodSelector        string
	ZeistdPodSelector         string
	NodeSelector              map[string]string
	Port                      int32
	ServiceMTLS               map[string]ServiceMTLSNames
}

// ServiceMTLSNames binds one generic trust domain to Kubernetes resources.
type ServiceMTLSNames struct {
	ServerNamespace   string
	ServerService     string
	ServerSecret      string
	ServerPodSelector string
	ServerPort        int32
	ClientNamespace   string
	ClientSecret      string
	ClientPodSelector string
	ClusterDomain     string
}

func (n Names) serviceMTLS(domain string) (ServiceMTLSNames, error) {
	configured, found := n.ServiceMTLS[domain]
	if !found {
		return ServiceMTLSNames{}, fmt.Errorf("service-mTLS domain %q is not configured", domain)
	}
	return configured, nil
}

// validateWebhookCanary keeps the candidate-root activation proof an atomic
// integration contract: a partial canary configuration would otherwise let a
// rollover advance without testing the candidate-signed endpoint.
func (n Names) validateWebhookCanary() error {
	if n.WebhookCanarySecret == "" || n.WebhookCanaryService == "" || n.WebhookCanaryConfiguration == "" {
		return fmt.Errorf("webhook canary secret, service, and configuration are required")
	}
	return nil
}

// StateSecretName returns the only authoritative issuer state location for a
// domain. Its private keys are never copied to consumer Secrets.
func StateSecretName(domain string) string { return StateSecretPrefix + domain + StateSecretSuffix }

// StateStore persists public rotation state and restricted issuer PEM in one
// Opaque Secret. The portable State deliberately does not duplicate PEM.
type StateStore struct {
	Client    kubernetes.Interface
	Namespace string
}

// Load implements rotation.StateStore.
func (s StateStore) Load(ctx context.Context, domain string) (rotation.VersionedState, error) {
	secret, err := s.Client.CoreV1().Secrets(s.Namespace).Get(ctx, StateSecretName(domain), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return rotation.VersionedState{}, rotation.ErrStateNotFound
	}
	if err != nil {
		return rotation.VersionedState{}, err
	}
	data, found := secret.Data[stateDataKey]
	if !found || len(data) == 0 {
		// A deployment may deliberately pre-create an empty, fixed-name Secret
		// so RBAC need not grant the issuer arbitrary Secret creation. It is the
		// same logical condition as no state at all, but unlike a partially
		// populated state Secret it is safe to bootstrap into.
		return rotation.VersionedState{}, rotation.ErrStateNotFound
	}
	var state rotation.State
	if err := json.Unmarshal(data, &state); err != nil {
		return rotation.VersionedState{}, fmt.Errorf("decode issuer state: %w", err)
	}
	if err := hydrateStateAuthorities(secret, &state); err != nil {
		return rotation.VersionedState{}, err
	}
	return rotation.VersionedState{State: state, Version: stateVersion(secret.ResourceVersion)}, nil
}

// Save implements rotation.StateStore with Kubernetes resourceVersion fencing.
func (s StateStore) Save(ctx context.Context, domain string, state rotation.State, version string) (rotation.VersionedState, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return rotation.VersionedState{}, fmt.Errorf("encode issuer state: %w", err)
	}
	secret, err := s.Client.CoreV1().Secrets(s.Namespace).Get(ctx, StateSecretName(domain), metav1.GetOptions{})
	if apierrors.IsNotFound(err) && version == "" {
		secret, err = s.Client.CoreV1().Secrets(s.Namespace).Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: StateSecretName(domain), Namespace: s.Namespace, Labels: map[string]string{annotationDomain: domain}},
			Type:       corev1.SecretTypeOpaque,
		}, metav1.CreateOptions{})
	}
	if err != nil {
		return rotation.VersionedState{}, err
	}
	if version == "" {
		if len(secret.Data[stateDataKey]) != 0 {
			return rotation.VersionedState{}, rotation.ErrConflict
		}
	} else if secret.ResourceVersion != resourceVersion(version) {
		return rotation.VersionedState{}, rotation.ErrConflict
	}
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	if err := storeStateAuthorities(secret, state); err != nil {
		return rotation.VersionedState{}, err
	}
	secret.Data[stateDataKey] = data
	if secret.Labels == nil {
		secret.Labels = map[string]string{}
	}
	secret.Labels[annotationDomain] = domain
	secret.Type = corev1.SecretTypeOpaque
	updated, err := s.Client.CoreV1().Secrets(s.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		return rotation.VersionedState{}, rotation.ErrConflict
	}
	if err != nil {
		return rotation.VersionedState{}, err
	}
	return rotation.VersionedState{State: state, Version: stateVersion(updated.ResourceVersion)}, nil
}

const stateVersionPrefix = "resourceVersion:"

func stateVersion(resourceVersion string) string { return stateVersionPrefix + resourceVersion }

func resourceVersion(version string) string {
	return strings.TrimPrefix(version, stateVersionPrefix)
}

// Lock holds and renews a Kubernetes Lease for one bounded reconciliation.
// It cancels Context as soon as renewal cannot prove continued ownership.
type Lock struct {
	client          kubernetes.Interface
	namespace       string
	name            string
	identity        string
	durationSeconds int32
	renewEvery      time.Duration
	now             func() time.Time
	context         context.Context
	cancel          context.CancelFunc
	done            chan struct{}

	mu         sync.RWMutex
	renewalErr error
	stopping   bool

	releaseOnce sync.Once
	releaseErr  error
}

// Context implements rotation.ContextLock. It is cancelled when the caller
// cancels Apply, Release begins, or the lease heartbeat loses ownership.
func (l *Lock) Context() context.Context { return l.context }

// Err implements rotation.ContextLock. It reports only a renewal ownership
// failure, not ordinary caller cancellation or successful Release.
func (l *Lock) Err() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.renewalErr
}

func (l *Lock) heartbeat() {
	defer close(l.done)
	ticker := time.NewTicker(l.renewEvery)
	defer ticker.Stop()
	for {
		select {
		case <-l.context.Done():
			return
		case <-ticker.C:
			if err := l.renew(); err != nil {
				l.fail(err)
				return
			}
		}
	}
}

func (l *Lock) fail(err error) {
	if err == nil {
		return
	}
	l.mu.Lock()
	// Cancellation is expected while Release drains the heartbeat (or when the
	// caller abandons the reconciliation). Do not turn that normal teardown
	// race into a false ownership-loss result.
	if !l.stopping && l.context.Err() == nil && l.renewalErr == nil {
		l.renewalErr = err
	}
	l.mu.Unlock()
	if l.Err() != nil {
		l.cancel()
	}
}

func (l *Lock) renew() error {
	timeout := l.renewEvery
	if timeout <= 0 || timeout > time.Duration(l.durationSeconds)*time.Second/2 {
		timeout = time.Duration(l.durationSeconds) * time.Second / 2
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	ctx, cancel := context.WithTimeout(l.context, timeout)
	defer cancel()
	lease, err := l.client.CoordinationV1().Leases(l.namespace).Get(ctx, l.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("rotation lease %q disappeared during renewal", l.name)
	}
	if err != nil {
		return fmt.Errorf("read rotation lease %q for renewal: %w", l.name, err)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != l.identity {
		return fmt.Errorf("rotation lease %q is no longer held by %q", l.name, l.identity)
	}
	now := metav1.NewMicroTime(l.now())
	seconds := l.durationSeconds
	lease.Spec.LeaseDurationSeconds = &seconds
	lease.Spec.RenewTime = &now
	if _, err := l.client.CoordinationV1().Leases(l.namespace).Update(ctx, lease, metav1.UpdateOptions{}); err != nil {
		if apierrors.IsConflict(err) {
			return fmt.Errorf("rotation lease %q changed during renewal: %w", l.name, rotation.ErrConflict)
		}
		return fmt.Errorf("renew rotation lease %q: %w", l.name, err)
	}
	return nil
}

// Release stops the heartbeat before clearing only the holder's own Lease
// ownership. A successful operation does not retain a lease through a long
// dual-trust overlap. The Lease object itself remains in place so a tightly
// scoped Role need not grant delete or arbitrary create permission.
func (l *Lock) Release(ctx context.Context) error {
	l.releaseOnce.Do(func() {
		l.mu.Lock()
		l.stopping = true
		l.mu.Unlock()
		l.cancel()
		<-l.done
		l.releaseErr = l.release(ctx)
	})
	return l.releaseErr
}

func (l *Lock) release(ctx context.Context) error {
	lease, err := l.client.CoordinationV1().Leases(l.namespace).Get(ctx, l.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != l.identity {
		return nil
	}
	lease.Spec.HolderIdentity = nil
	lease.Spec.RenewTime = nil
	lease.Spec.AcquireTime = nil
	_, err = l.client.CoordinationV1().Leases(l.namespace).Update(ctx, lease, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		return rotation.ErrConflict
	}
	return err
}

// Locker obtains a short-lived domain Lease. Identity must be a unique
// process/Pod identity, never a static deployment name.
type Locker struct {
	Client        kubernetes.Interface
	Namespace     string
	Identity      string
	Duration      time.Duration
	RenewInterval time.Duration
	// Now allows deterministic fencing tests. It must return UTC-safe wall
	// time; zero means time.Now().UTC().
	Now func() time.Time
}

// Acquire implements rotation.Locker.
func (l Locker) Acquire(ctx context.Context, domain string) (rotation.Lock, error) {
	if l.Identity == "" {
		return nil, fmt.Errorf("lease identity is required")
	}
	seconds := int32((l.Duration + time.Second - 1) / time.Second)
	if seconds <= 0 {
		seconds = 60
	}
	duration := time.Duration(seconds) * time.Second
	renewEvery, err := l.renewInterval(duration)
	if err != nil {
		return nil, err
	}
	now := metav1.NewMicroTime(l.now())
	name := "zeist-pki-" + domain
	existing, err := l.Client.CoordinationV1().Leases(l.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		lease, createErr := l.Client.CoordinationV1().Leases(l.Namespace).Create(ctx, &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: l.Namespace},
			Spec:       coordinationv1.LeaseSpec{HolderIdentity: &l.Identity, LeaseDurationSeconds: &seconds, AcquireTime: &now, RenewTime: &now},
		}, metav1.CreateOptions{})
		if createErr != nil {
			return nil, createErr
		}
		return l.newLock(ctx, lease.Name, seconds, renewEvery), nil
	}
	if err != nil {
		return nil, err
	}
	// Identity is diagnostic evidence, not re-entrant ownership. Accepting an
	// unexpired Lease held by the same identity would let two invocations inside
	// one Pod publish concurrently, so every non-empty live holder fences a new
	// acquisition until it releases or expires.
	if !leaseExpired(existing, l.now()) && existing.Spec.HolderIdentity != nil && *existing.Spec.HolderIdentity != "" {
		return nil, fmt.Errorf("rotation lease %q is held", name)
	}
	existing.Spec.HolderIdentity = &l.Identity
	existing.Spec.LeaseDurationSeconds = &seconds
	existing.Spec.AcquireTime = &now
	existing.Spec.RenewTime = &now
	updated, err := l.Client.CoordinationV1().Leases(l.Namespace).Update(ctx, existing, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		return nil, fmt.Errorf("rotation lease %q changed while acquiring: %w", name, rotation.ErrConflict)
	}
	if err != nil {
		return nil, err
	}
	return l.newLock(ctx, updated.Name, seconds, renewEvery), nil
}

func (l Locker) now() time.Time {
	if l.Now != nil {
		return l.Now().UTC()
	}
	return time.Now().UTC()
}

func (l Locker) renewInterval(duration time.Duration) (time.Duration, error) {
	interval := l.RenewInterval
	if interval <= 0 {
		interval = duration / 3
	}
	if interval <= 0 || interval >= duration {
		return 0, fmt.Errorf("rotation lease renewal interval must be positive and less than its duration")
	}
	return interval, nil
}

func (l Locker) newLock(parent context.Context, name string, seconds int32, renewEvery time.Duration) *Lock {
	ctx, cancel := context.WithCancel(parent)
	lock := &Lock{
		client: l.Client, namespace: l.Namespace, name: name, identity: l.Identity,
		durationSeconds: seconds, renewEvery: renewEvery, now: l.now,
		context: ctx, cancel: cancel, done: make(chan struct{}),
	}
	go lock.heartbeat()
	return lock
}

func leaseExpired(lease *coordinationv1.Lease, now time.Time) bool {
	if lease.Spec.LeaseDurationSeconds == nil || lease.Spec.RenewTime == nil {
		return true
	}
	return lease.Spec.RenewTime.Add(time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second).Before(now)
}

// Discoverer gives the portable state machine an exact selected-node target
// snapshot. A later node change naturally requires a new generation.
type Discoverer struct {
	Client kubernetes.Interface
	Names  Names
}

// Discover implements rotation.Discoverer.
func (d Discoverer) Discover(ctx context.Context, domain rotation.Domain) ([]rotation.Target, error) {
	switch domain.Profile {
	case rotation.ProfileWebhook:
		// The API-server canary is necessary but not sufficient: every Ready
		// manager replica can independently serve the webhook leaf. Include each
		// one in the durable target snapshot so a rollover cannot retire its old
		// root until every serving process reports its in-memory swap.
		targets := []rotation.Target{{
			ID:       bindingTargetID(domain),
			Evidence: map[string]string{"role": "webhook", "probeOnly": "true"},
		}}
		pods, err := d.Client.CoreV1().Pods(d.Names.Namespace).List(ctx, metav1.ListOptions{LabelSelector: webhookPodSelector(d.Names)})
		if err != nil {
			return nil, err
		}
		for index := range pods.Items {
			pod := &pods.Items[index]
			if pod.UID == "" || !podReady(pod) {
				continue
			}
			targets = append(targets, rotation.Target{
				ID:       "manager:" + string(pod.UID),
				Evidence: map[string]string{"role": "webhook", "podName": pod.Name},
			})
		}
		sort.Slice(targets, func(first, second int) bool { return targets[first].ID < targets[second].ID })
		return targets, nil
	case rotation.ProfileMTLS:
		nodes, err := d.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: selectorString(d.Names.NodeSelector)})
		if err != nil {
			return nil, err
		}
		port := d.Names.Port
		if port == 0 {
			port = 10443
		}
		targets := []rotation.Target{{ID: bindingTargetID(domain), Evidence: map[string]string{"role": "client", "probeOnly": "true"}}}
		serverTargets := 0
		for _, node := range nodes.Items {
			for _, address := range node.Status.Addresses {
				if address.Type == corev1.NodeInternalIP && net.ParseIP(address.Address) != nil {
					targets = append(targets, rotation.Target{ID: "node:" + string(node.UID), Evidence: map[string]string{"role": "server", "nodeName": node.Name, "internalIP": address.Address, "port": fmt.Sprintf("%d", port)}})
					serverTargets++
					break
				}
			}
		}
		pods, err := d.Client.CoreV1().Pods(d.Names.Namespace).List(ctx, metav1.ListOptions{LabelSelector: managerPodSelector(d.Names)})
		if err != nil {
			return nil, err
		}
		for _, pod := range pods.Items {
			if pod.UID == "" || !podReady(&pod) {
				continue
			}
			targets = append(targets, rotation.Target{ID: "manager:" + string(pod.UID), Evidence: map[string]string{"role": "client", "podName": pod.Name}})
		}
		if serverTargets == 0 {
			return nil, fmt.Errorf("no selected Nodes have an InternalIP")
		}
		sort.Slice(targets, func(first, second int) bool { return targets[first].ID < targets[second].ID })
		return targets, nil
	case rotation.ProfileServiceMTLS:
		configured, err := d.Names.serviceMTLS(domain.Name)
		if err != nil {
			return nil, err
		}
		targets := []rotation.Target{{ID: bindingTargetID(domain), Evidence: map[string]string{"role": "server", "probeOnly": "true"}}}
		serverTargets, err := d.servicePodTargets(ctx, configured.ServerNamespace, configured.ServerPodSelector, "server")
		if err != nil {
			return nil, fmt.Errorf("discover service-mTLS server consumers: %w", err)
		}
		clientTargets, err := d.servicePodTargets(ctx, configured.ClientNamespace, configured.ClientPodSelector, "client")
		if err != nil {
			return nil, fmt.Errorf("discover service-mTLS client consumers: %w", err)
		}
		targets = append(targets, serverTargets...)
		targets = append(targets, clientTargets...)
		sort.Slice(targets, func(first, second int) bool { return targets[first].ID < targets[second].ID })
		return targets, nil
	default:
		return nil, fmt.Errorf("unsupported domain profile %q", domain.Profile)
	}
}

func bindingTargetID(domain rotation.Domain) string {
	binding := domain.Metadata["bindingHash"]
	if binding == "" {
		binding = domain.ConfigurationHash
	}
	return "probe:" + domain.Name + ":" + binding
}

func (d Discoverer) servicePodTargets(ctx context.Context, namespace, selector, role string) ([]rotation.Target, error) {
	pods, err := d.Client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	targets := make([]rotation.Target, 0, len(pods.Items))
	for index := range pods.Items {
		pod := &pods.Items[index]
		if pod.UID == "" || !podReady(pod) {
			continue
		}
		id, err := contractv1.PodTargetID(role, string(pod.UID))
		if err != nil {
			return nil, err
		}
		targets = append(targets, rotation.Target{ID: id, Evidence: map[string]string{
			"role": role, "podName": pod.Name, "podNamespace": pod.Namespace, "podUID": string(pod.UID),
		}})
	}
	return targets, nil
}

func managerPodSelector(names Names) string {
	return names.ManagerPodSelector
}

func webhookPodSelector(names Names) string {
	return names.WebhookPodSelector
}

func zeistdPodSelector(names Names) string {
	return names.ZeistdPodSelector
}

func podReady(pod *corev1.Pod) bool {
	if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func selectorString(selector map[string]string) string {
	keys := make([]string, 0, len(selector))
	for key := range selector {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+selector[key])
	}
	return strings.Join(parts, ",")
}

// PublicationMaterial carries Secret data after the portable Issuer made a
// generation. Publisher only owns distribution, annotations, and atomic write.
type PublicationMaterial struct {
	WebhookTLS       map[string][]byte
	WebhookCanaryTLS map[string][]byte
	ServerTLS        map[string][]byte
	ClientTLS        map[string][]byte
	// TrustBundle is the normal consumer trust set. CanaryTrustBundle is the
	// single-root trust set for the candidate-only admission endpoint, which
	// proves that the API server actually loaded the candidate root.
	TrustBundle       []byte
	CanaryTrustBundle []byte
}

// Publisher atomically publishes fixed Zeist-compatible Secret outputs.
type Publisher struct {
	Client kubernetes.Interface
	Names  Names
	// Material is retained as an optional compatibility hook for embedders that
	// construct a Publication outside the bundled Kubernetes Issuer. The normal
	// path carries transient material in Publication.Opaque and never persists
	// it in rotation.State.
	Material func(rotation.Publication) (PublicationMaterial, error)
}

func (p Publisher) requireWebhookCanary() error { return p.Names.validateWebhookCanary() }

// Publish implements rotation.Publisher.
func (p Publisher) Publish(ctx context.Context, publication rotation.Publication) error {
	material, err := publicationMaterial(publication, p.Material)
	if err != nil {
		return err
	}
	switch publication.Domain {
	case "webhook":
		if err := p.requireWebhookCanary(); err != nil {
			return err
		}
		// A candidate-only endpoint establishes that the API server has loaded
		// the candidate root before the production webhook leaf changes. Keep
		// this order on every replay: canary leaf, both trust configurations,
		// then the production leaf.
		if err := p.applySecret(ctx, p.Names.Namespace, p.Names.WebhookCanarySecret, corev1.SecretTypeTLS, material.WebhookCanaryTLS, publication, "canary"); err != nil {
			return err
		}
		if err := p.publishWebhookTrust(ctx, material.TrustBundle, material.CanaryTrustBundle); err != nil {
			return err
		}
		return p.applySecret(ctx, p.Names.Namespace, p.Names.WebhookSecret, corev1.SecretTypeTLS, material.WebhookTLS, publication, "webhook")
	case "mtls":
		if err := p.applySecret(ctx, p.Names.Namespace, p.Names.ServerSecret, corev1.SecretTypeTLS, material.ServerTLS, publication, "server"); err != nil {
			return err
		}
		return p.applySecret(ctx, p.Names.Namespace, p.Names.ClientSecret, corev1.SecretTypeTLS, material.ClientTLS, publication, "client")
	default:
		configured, err := p.Names.serviceMTLS(publication.Domain)
		if err != nil {
			return err
		}
		if err := p.applySecret(ctx, configured.ServerNamespace, configured.ServerSecret, corev1.SecretTypeTLS, material.ServerTLS, publication, "server"); err != nil {
			return err
		}
		return p.applySecret(ctx, configured.ClientNamespace, configured.ClientSecret, corev1.SecretTypeTLS, material.ClientTLS, publication, "client")
	}
}

func (p Publisher) applySecret(ctx context.Context, namespace, name string, secretType corev1.SecretType, data map[string][]byte, publication rotation.Publication, role string) error {
	if len(data) == 0 {
		return fmt.Errorf("publication has no Secret data for %q", name)
	}
	material, found := publication.Materials[role]
	if !found {
		return fmt.Errorf("publication has no %q fingerprint material", role)
	}
	annotations := publicationAnnotations(publication, material)
	secret, err := p.Client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = p.Client.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Annotations: annotations}, Type: secretType, Data: cloneData(data)}, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if hasSecretMaterial(secret) {
		// The PKI owns only its five fencing annotations. Controllers and
		// admission plugins may add their own annotations, which must neither
		// prevent replay nor be discarded during an otherwise idempotent publish.
		if managedAnnotationsMatch(secret.Annotations, annotations) && equalData(secret.Data, data) && secret.Type == secretType {
			return nil
		}
		if secret.Annotations[annotationDomain] == publication.Domain && secret.Annotations[annotationGeneration] == fmt.Sprintf("%d", publication.Generation) && secret.Annotations[annotationOperation] == publication.OperationID {
			return fmt.Errorf("published Secret %s data does not match its operation-fenced generation", name)
		}
		canAdoptCanary := role == "canary" && (secret.Annotations[annotationDomain] == "" || secret.Annotations[annotationDomain] == publication.Domain)
		if publication.AdoptExisting && (sameLeafCredentials(secret.Data, data) || canAdoptCanary) {
			// Guarded recovery has already parsed and verified this exact old
			// primary leaf/key pair against the operator-confirmed root. It may
			// only replace primary trust material and fencing annotations. The
			// separate canary is deliberately replaceable here: recovery must
			// install a leaf signed by the newly persisted candidate root before
			// it can prove API-server activation.
			secret.Type = secretType
			secret.Data = cloneData(data)
			secret.Annotations = mergeManagedAnnotations(secret.Annotations, annotations)
			_, err = p.Client.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
			return err
		}
		if secret.Annotations[annotationDomain] != publication.Domain {
			return fmt.Errorf("refusing to overwrite existing managed Secret %s from domain %q", name, secret.Annotations[annotationDomain])
		}
		// State persisted this generation before Issue or Publish. A managed
		// Secret from the same domain with an older operation is the expected
		// predecessor during renewal, endpoint updates, and root rollover.
		// Update retains Kubernetes' resourceVersion precondition so a concurrent
		// writer still fails rather than silently winning.
	}
	secret.Type = secretType
	secret.Data = cloneData(data)
	secret.Annotations = mergeManagedAnnotations(secret.Annotations, annotations)
	_, err = p.Client.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

func sameLeafCredentials(existing, incoming map[string][]byte) bool {
	return len(existing["tls.crt"]) != 0 && len(existing["tls.key"]) != 0 &&
		bytes.Equal(existing["tls.crt"], incoming["tls.crt"]) &&
		bytes.Equal(existing["tls.key"], incoming["tls.key"])
}

func publicationMaterial(publication rotation.Publication, fallback func(rotation.Publication) (PublicationMaterial, error)) (PublicationMaterial, error) {
	switch material := publication.Opaque.(type) {
	case PublicationMaterial:
		return material, nil
	case *PublicationMaterial:
		if material == nil {
			break
		}
		return *material, nil
	}
	if fallback != nil {
		return fallback(publication)
	}
	return PublicationMaterial{}, fmt.Errorf("publication has no transient Kubernetes Secret material")
}

func hasSecretMaterial(secret *corev1.Secret) bool {
	for _, value := range secret.Data {
		if len(value) != 0 {
			return true
		}
	}
	return false
}

func equalData(first, second map[string][]byte) bool {
	if len(first) != len(second) {
		return false
	}
	for key, value := range first {
		other, found := second[key]
		if !found || string(value) != string(other) {
			return false
		}
	}
	return true
}

func managedAnnotationsMatch(existing, managed map[string]string) bool {
	for key, value := range managed {
		if existing[key] != value {
			return false
		}
	}
	return true
}

func mergeManagedAnnotations(existing, managed map[string]string) map[string]string {
	merged := make(map[string]string, len(existing)+len(managed))
	for key, value := range existing {
		merged[key] = value
	}
	for key, value := range managed {
		merged[key] = value
	}
	return merged
}

func publicationAnnotations(publication rotation.Publication, material rotation.MaterialFingerprint) map[string]string {
	return map[string]string{
		annotationDomain: publication.Domain, annotationGeneration: fmt.Sprintf("%d", publication.Generation),
		annotationOperation: publication.OperationID, annotationLeafFingerprint: material.LeafFingerprint,
		annotationTrustFingerprint: material.TrustFingerprint,
	}
}

func cloneData(data map[string][]byte) map[string][]byte {
	copy := make(map[string][]byte, len(data))
	for key, value := range data {
		copy[key] = append([]byte(nil), value...)
	}
	return copy
}

// AcknowledgementLeaseName makes per-consumer observation names stable and
// readable while avoiding direct use of user-controlled pod names.
func AcknowledgementLeaseName(domain, targetID string) string {
	return contractv1.AcknowledgementLeaseName(domain, targetID)
}

// AcknowledgementLeaseData is retained as an alias for existing integrations.
// New consumers should import contract/v1 directly.
type AcknowledgementLeaseData = contractv1.Acknowledgement

const acknowledgementAnnotation = contractv1.AcknowledgementAnnotation

// Verifier checks exact consumer acknowledgement Leases. Its transport probe
// hook allows the Zeist integration to additionally prove live TLS endpoints.
type Verifier struct {
	Client kubernetes.Interface
	Names  Names
	Probe  func(context.Context, rotation.VerificationRequest) error
}

// Verify implements rotation.Verifier.
func (v Verifier) Verify(ctx context.Context, request rotation.VerificationRequest) ([]rotation.Acknowledgement, error) {
	needsProbe := false
	for _, target := range request.Targets {
		if target.Evidence["probeOnly"] == "true" {
			needsProbe = true
			break
		}
	}
	if needsProbe && v.Probe == nil {
		return nil, fmt.Errorf("verification requires a live probe for probe-only targets")
	}
	if v.Probe != nil {
		if err := v.Probe(ctx, request); err != nil {
			return nil, err
		}
	}
	pods, err := v.acknowledgementPodIndex(ctx, request.Targets)
	if err != nil {
		return nil, err
	}
	acknowledgements := make([]rotation.Acknowledgement, 0, len(request.Targets))
	for _, target := range request.Targets {
		expected, found := request.Publication.MaterialFor(target)
		if !found {
			return nil, fmt.Errorf("publication has no fingerprint material for %q", target.ID)
		}
		if target.Evidence["probeOnly"] == "true" {
			acknowledgements = append(acknowledgements, rotation.Acknowledgement{TargetID: target.ID, Generation: request.Generation, LeafFingerprint: expected.LeafFingerprint, TrustFingerprint: expected.TrustFingerprint, ObservedAt: time.Now().UTC()})
			continue
		}
		lease, err := v.Client.CoordinationV1().Leases(acknowledgementNamespace(v.Names)).Get(ctx, AcknowledgementLeaseName(request.Domain.Name, target.ID), metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("read acknowledgement for %q: %w", target.ID, err)
		}
		if !acknowledgementLeaseLive(lease, time.Now().UTC()) {
			return nil, fmt.Errorf("acknowledgement for %q is expired or lacks a renewable lease", target.ID)
		}
		if err := pods.verify(target, *lease.Spec.HolderIdentity); err != nil {
			return nil, fmt.Errorf("acknowledgement for %q is not owned by its expected consumer: %w", target.ID, err)
		}
		data, err := contractv1.DecodeAcknowledgement(lease.Annotations[acknowledgementAnnotation])
		if err != nil {
			return nil, fmt.Errorf("decode acknowledgement for %q: %w", target.ID, err)
		}
		if data.Generation != request.Generation || data.LeafFingerprint != expected.LeafFingerprint || data.TrustFingerprint != expected.TrustFingerprint {
			return nil, fmt.Errorf("acknowledgement for %q is not generation %d", target.ID, request.Generation)
		}
		acknowledgements = append(acknowledgements, rotation.Acknowledgement{TargetID: target.ID, Generation: data.Generation, LeafFingerprint: data.LeafFingerprint, TrustFingerprint: data.TrustFingerprint, ObservedAt: lease.Spec.RenewTime.Time})
	}
	return acknowledgements, nil
}

// acknowledgementPodIndex snapshots the current Ready consumers selected by
// this integration. A lease annotation is only evidence after its holder is
// tied to the exact consumer target that produced it.
type acknowledgementPodIndex struct {
	managers map[string]*corev1.Pod
	zeistd   map[string]*corev1.Pod
	nodes    map[string]*corev1.Node
	pods     map[string]*corev1.Pod
}

func (v Verifier) acknowledgementPodIndex(ctx context.Context, targets []rotation.Target) (acknowledgementPodIndex, error) {
	index := acknowledgementPodIndex{
		managers: make(map[string]*corev1.Pod),
		zeistd:   make(map[string]*corev1.Pod),
		nodes:    make(map[string]*corev1.Node),
		pods:     make(map[string]*corev1.Pod),
	}
	needManagers, needZeistd := false, false
	for _, target := range targets {
		if target.Evidence["probeOnly"] == "true" {
			continue
		}
		kind, _, err := acknowledgementTargetIdentity(target)
		if err != nil {
			return acknowledgementPodIndex{}, err
		}
		switch kind {
		case "manager":
			needManagers = true
		case "zeistd":
			needZeistd = true
		case "pod":
			podName, namespace := target.Evidence["podName"], target.Evidence["podNamespace"]
			if podName == "" || namespace == "" {
				return acknowledgementPodIndex{}, fmt.Errorf("Pod target %q has incomplete identity evidence", target.ID)
			}
			pod, getErr := v.Client.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
			if getErr != nil {
				return acknowledgementPodIndex{}, fmt.Errorf("read selected Pod %s/%s: %w", namespace, podName, getErr)
			}
			if string(pod.UID) != target.Evidence["podUID"] || !podReady(pod) {
				return acknowledgementPodIndex{}, fmt.Errorf("selected Pod %s/%s no longer matches Ready target %q", namespace, podName, target.ID)
			}
			index.pods[string(pod.UID)] = pod
		}
	}
	if needManagers {
		selectors := []string{managerPodSelector(v.Names), webhookPodSelector(v.Names)}
		seenSelectors := make(map[string]struct{}, len(selectors))
		for _, selector := range selectors {
			if selector == "" {
				continue
			}
			if _, found := seenSelectors[selector]; found {
				continue
			}
			seenSelectors[selector] = struct{}{}
			pods, err := v.Client.CoreV1().Pods(v.Names.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
			if err != nil {
				return acknowledgementPodIndex{}, fmt.Errorf("list selected manager Pods: %w", err)
			}
			for itemIndex := range pods.Items {
				pod := &pods.Items[itemIndex]
				if pod.UID != "" && podReady(pod) {
					index.managers[string(pod.UID)] = pod
				}
			}
		}
	}
	if needZeistd {
		// A target's ID contains the Node UID while its evidence carries the
		// Node name needed to identify the local zeistd Pod. Resolve the name
		// again here so a replacement Node cannot satisfy an acknowledgement
		// for an old target snapshot merely by reusing its name.
		for _, target := range targets {
			kind, expectedUID, identityErr := acknowledgementTargetIdentity(target)
			if identityErr != nil || kind != "zeistd" {
				continue
			}
			nodeName := target.Evidence["nodeName"]
			if nodeName == "" {
				return acknowledgementPodIndex{}, fmt.Errorf("node target %q has no nodeName evidence", target.ID)
			}
			if _, found := index.nodes[nodeName]; found {
				continue
			}
			node, nodeErr := v.Client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
			if nodeErr != nil {
				return acknowledgementPodIndex{}, fmt.Errorf("read selected Node %q: %w", nodeName, nodeErr)
			}
			if string(node.UID) != expectedUID {
				return acknowledgementPodIndex{}, fmt.Errorf("selected Node %q has UID %q, want target UID %q", nodeName, node.UID, expectedUID)
			}
			index.nodes[nodeName] = node
		}
		pods, err := v.Client.CoreV1().Pods(v.Names.Namespace).List(ctx, metav1.ListOptions{LabelSelector: zeistdPodSelector(v.Names)})
		if err != nil {
			return acknowledgementPodIndex{}, fmt.Errorf("list selected zeistd Pods: %w", err)
		}
		for itemIndex := range pods.Items {
			pod := &pods.Items[itemIndex]
			if pod.UID != "" && podReady(pod) {
				index.zeistd[string(pod.UID)] = pod
			}
		}
	}
	return index, nil
}

func (p acknowledgementPodIndex) verify(target rotation.Target, holderIdentity string) error {
	kind, expectedID, err := acknowledgementTargetIdentity(target)
	if err != nil {
		return err
	}
	switch kind {
	case "manager":
		if holderIdentity != expectedID {
			return fmt.Errorf("lease holder %q does not match manager Pod UID %q", holderIdentity, expectedID)
		}
		if _, found := p.managers[expectedID]; !found {
			return fmt.Errorf("manager Pod UID %q is not a selected Ready consumer", expectedID)
		}
		return nil
	case "zeistd":
		pod, found := p.zeistd[holderIdentity]
		if !found {
			return fmt.Errorf("lease holder %q is not a selected Ready zeistd Pod", holderIdentity)
		}
		nodeName := target.Evidence["nodeName"]
		if nodeName == "" {
			return fmt.Errorf("node target has no nodeName evidence")
		}
		if pod.Spec.NodeName != nodeName {
			return fmt.Errorf("zeistd Pod %q is scheduled on Node %q, want %q", pod.Name, pod.Spec.NodeName, nodeName)
		}
		node, found := p.nodes[nodeName]
		if !found || string(node.UID) != expectedID {
			return fmt.Errorf("Node %q no longer matches target UID %q", nodeName, expectedID)
		}
		return nil
	case "pod":
		if holderIdentity != expectedID {
			return fmt.Errorf("lease holder %q does not match Pod UID %q", holderIdentity, expectedID)
		}
		if _, found := p.pods[expectedID]; !found {
			return fmt.Errorf("Pod UID %q is not a selected Ready consumer", expectedID)
		}
		return nil
	default:
		return fmt.Errorf("unsupported acknowledgement target kind %q", kind)
	}
}

func acknowledgementTargetIdentity(target rotation.Target) (kind, identity string, err error) {
	if podUID := target.Evidence["podUID"]; podUID != "" {
		expected, targetErr := contractv1.PodTargetID(target.Evidence["role"], podUID)
		if targetErr != nil || target.ID != expected {
			return "", "", fmt.Errorf("service acknowledgement target has invalid Pod identity %q", target.ID)
		}
		return "pod", podUID, nil
	}
	switch target.Evidence["role"] {
	case "client", "webhook":
		identity, found := strings.CutPrefix(target.ID, "manager:")
		if !found || identity == "" {
			return "", "", fmt.Errorf("%s acknowledgement target has invalid manager identity %q", target.Evidence["role"], target.ID)
		}
		return "manager", identity, nil
	case "server":
		identity, found := strings.CutPrefix(target.ID, "node:")
		if !found || identity == "" {
			return "", "", fmt.Errorf("server acknowledgement target has invalid Node identity %q", target.ID)
		}
		return "zeistd", identity, nil
	default:
		return "", "", fmt.Errorf("acknowledgement target %q has unsupported role %q", target.ID, target.Evidence["role"])
	}
}

func acknowledgementLeaseLive(lease *coordinationv1.Lease, now time.Time) bool {
	if lease == nil || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" ||
		lease.Spec.RenewTime == nil || lease.Spec.LeaseDurationSeconds == nil || *lease.Spec.LeaseDurationSeconds <= 0 {
		return false
	}
	return !lease.Spec.RenewTime.Add(time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second).Before(now)
}

func acknowledgementNamespace(names Names) string {
	if names.AcknowledgementNamespace != "" {
		return names.AcknowledgementNamespace
	}
	return names.Namespace
}

// EncodeAcknowledgement encodes credential-free in-memory evidence for a
// consumer to put in its acknowledgement Lease annotation.
func EncodeAcknowledgement(data AcknowledgementLeaseData) (string, error) {
	return contractv1.EncodeAcknowledgement(data)
}

// DecodeCAData is a narrow helper for an adapter that stores restricted CA
// material. It makes accidental publication via a consumer Secret obvious.
func DecodeCAData(secret *corev1.Secret, key string) ([]byte, error) {
	if secret == nil {
		return nil, errors.New("issuer state Secret is required")
	}
	data, found := secret.Data[key]
	if !found || len(data) == 0 {
		return nil, fmt.Errorf("issuer state Secret has no %q", key)
	}
	return append([]byte(nil), data...), nil
}

// StateSecretDataKeys returns the intended sensitive-state key set for RBAC
// audits and tests. It never returns actual key material.
func StateSecretDataKeys() []string {
	return []string{activeCAKey, activeCAKeyKey, candidateCAKey, candidateCAKeyKey, stateDataKey}
}

// ResourceName returns a strict namespaced Secret resource identity used in
// error messages without ever printing its contents.
func ResourceName(namespace, name string) string {
	return types.NamespacedName{Namespace: namespace, Name: name}.String()
}

var _ rotation.StateStore = StateStore{}
var _ rotation.Locker = Locker{}
var _ rotation.ContextLock = (*Lock)(nil)
var _ rotation.Discoverer = Discoverer{}
var _ rotation.Publisher = Publisher{}
var _ rotation.Verifier = Verifier{}
