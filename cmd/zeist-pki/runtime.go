package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/zeisthq/zeist-pki/config"
	pkikubernetes "github.com/zeisthq/zeist-pki/integration/kubernetes"
	"github.com/zeisthq/zeist-pki/rotation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	// ErrIssuerUnavailable is returned by the intentionally read-only offline
	// planning runtime rather than attempting a partially configured mutation.
	ErrIssuerUnavailable = errors.New("issuer and recovery adapters are not configured")
)

// RuntimeOptions are the non-secret inputs a command factory needs to build a
// runtime. The config file contains names and policy only; credentials are
// obtained by client-go from the selected Kubernetes configuration.
type RuntimeOptions struct {
	Config     config.File
	RESTConfig *rest.Config
	Identity   string
}

// Runtime is deliberately small so command behavior can be tested without a
// Kubernetes API server and adapters can be assembled outside the CLI parser.
// Load is read-only. Apply, Verify, and Recover are explicit operations with
// no implicit fallbacks.
type Runtime interface {
	Load(context.Context, string) (rotation.VersionedState, error)
	Apply(context.Context, rotation.Domain) (rotation.Result, error)
	Verify(context.Context, rotation.VerificationRequest) ([]rotation.Acknowledgement, error)
	Recover(context.Context, rotation.Domain, string) (rotation.Result, error)
}

// RuntimeFactory constructs all Kubernetes-backed collaborators after command
// flags and configuration have been validated. Keeping this boundary here
// avoids embedding Kubernetes control-plane assumptions in rotation.
type RuntimeFactory interface {
	Build(context.Context, RuntimeOptions) (Runtime, error)
}

// RecoveryFunc lets a concrete integration expose guarded recovery without
// coupling command parsing to its storage layout.
type RecoveryFunc func(context.Context, rotation.Domain, string) (rotation.Result, error)

// ReconcilerRuntime adapts the portable reconciler and verifier to Runtime.
// It is intended for the production Kubernetes factory as well as focused
// integration tests.
type ReconcilerRuntime struct {
	Store       rotation.StateStore
	Reconciler  rotation.Reconciler
	Verifier    rotation.Verifier
	RecoverFunc RecoveryFunc
}

// offlinePlanRuntime intentionally exposes no Kubernetes state. It exists only
// for `plan` when no in-cluster or kubeconfig credential source is available,
// yielding the deterministic fresh-bootstrap preview without a write or a key
// generation operation.
type offlinePlanRuntime struct{}

func (offlinePlanRuntime) Load(context.Context, string) (rotation.VersionedState, error) {
	return rotation.VersionedState{}, rotation.ErrStateNotFound
}

func (offlinePlanRuntime) Apply(context.Context, rotation.Domain) (rotation.Result, error) {
	return rotation.Result{}, ErrIssuerUnavailable
}

func (offlinePlanRuntime) Verify(context.Context, rotation.VerificationRequest) ([]rotation.Acknowledgement, error) {
	return nil, ErrIssuerUnavailable
}

func (offlinePlanRuntime) Recover(context.Context, rotation.Domain, string) (rotation.Result, error) {
	return rotation.Result{}, ErrIssuerUnavailable
}

func (r ReconcilerRuntime) Load(ctx context.Context, domain string) (rotation.VersionedState, error) {
	if r.Store == nil {
		return rotation.VersionedState{}, fmt.Errorf("runtime state store: %w", ErrIssuerUnavailable)
	}
	return r.Store.Load(ctx, domain)
}

func (r ReconcilerRuntime) Apply(ctx context.Context, domain rotation.Domain) (rotation.Result, error) {
	return r.Reconciler.Apply(ctx, domain)
}

func (r ReconcilerRuntime) Verify(ctx context.Context, request rotation.VerificationRequest) ([]rotation.Acknowledgement, error) {
	if r.Verifier == nil {
		return nil, fmt.Errorf("runtime verifier: %w", ErrIssuerUnavailable)
	}
	return r.Verifier.Verify(ctx, request)
}

func (r ReconcilerRuntime) Recover(ctx context.Context, domain rotation.Domain, confirmedFingerprint string) (rotation.Result, error) {
	if r.RecoverFunc == nil {
		return rotation.Result{}, fmt.Errorf("recover %q: %w", domain.Name, ErrIssuerUnavailable)
	}
	return r.RecoverFunc(ctx, domain, confirmedFingerprint)
}

// kubernetesRuntimeFactory assembles the deliberately small Kubernetes
// adapter. It uses client-go only at this outer integration boundary; pki and
// rotation remain portable packages.
type kubernetesRuntimeFactory struct{}

func (kubernetesRuntimeFactory) Build(_ context.Context, options RuntimeOptions) (Runtime, error) {
	if options.RESTConfig == nil {
		return nil, fmt.Errorf("Kubernetes REST configuration is required")
	}
	client, err := kubernetes.NewForConfig(options.RESTConfig)
	if err != nil {
		return nil, fmt.Errorf("build Kubernetes client: %w", err)
	}
	names := pkikubernetes.Names{
		Namespace: options.Config.Namespace, AcknowledgementNamespace: options.Config.AcknowledgementsNamespace(),
		WebhookSecret: options.Config.Webhook.Secret, WebhookService: options.Config.Webhook.Service,
		WebhookCanarySecret: options.Config.Webhook.CanarySecret, WebhookCanaryService: options.Config.Webhook.CanaryService,
		WebhookCanaryConfiguration: options.Config.Webhook.CanaryConfiguration,
		WebhookCanaryResourcePath:  options.Config.Webhook.CanaryResourcePath,
		WebhookCanaryAnnotation:    options.Config.Webhook.CanaryAnnotation,
		APIServerEndpoints:         options.Config.Webhook.APIServerEndpoints,
		ServerSecret:               options.Config.MTLS.ServerSecret, ClientSecret: options.Config.MTLS.ClientSecret,
		RunnerService: options.Config.MTLS.Service, NodeSelector: options.Config.MTLS.NodeSelector, Port: options.Config.MTLS.Port,
		WebhookPodSelector:        selectorFromMap(options.Config.Webhook.PodSelector),
		ManagerPodSelector:        selectorFromMap(options.Config.MTLS.ClientPodSelector),
		ZeistdPodSelector:         selectorFromMap(options.Config.MTLS.ServerPodSelector),
		WebhookConfigurationNames: append([]string(nil), options.Config.Webhook.ConfigurationNames...),
		ServiceMTLS:               make(map[string]pkikubernetes.ServiceMTLSNames, len(options.Config.ServiceMTLS)),
	}
	for _, service := range options.Config.ServiceMTLS {
		names.ServiceMTLS[service.Name] = pkikubernetes.ServiceMTLSNames{
			ServerNamespace: service.Server.Namespace, ServerService: service.Server.Service, ServerSecret: service.Server.Secret,
			ServerPodSelector: selectorFromMap(service.Server.PodSelector), ServerPort: service.Server.Port,
			ServerProbeOnly: service.Server.ProbeOnly,
			ClientNamespace: service.Client.Namespace, ClientSecret: service.Client.Secret,
			ClientPodSelector: selectorFromMap(service.Client.PodSelector), ClusterDomain: service.EffectiveClusterDomain(),
		}
	}
	store := pkikubernetes.StateStore{Client: client, Namespace: names.Namespace}
	issuer := pkikubernetes.Issuer{Client: client, Names: names}
	canary, err := pkikubernetes.NewWebhookAdmissionCanary(options.RESTConfig, names.APIServerEndpoints, names.WebhookCanaryResourcePath, names.WebhookCanaryAnnotation)
	if err != nil {
		return nil, fmt.Errorf("configure webhook activation canary: %w", err)
	}
	verifier := pkikubernetes.Verifier{Client: client, Names: names, Probe: pkikubernetes.LiveProbe(client, names, canary)}
	locker := pkikubernetes.Locker{Client: client, Namespace: names.Namespace, Identity: options.Identity}
	reconciler := rotation.Reconciler{
		Store:      store,
		Locker:     locker,
		Publisher:  pkikubernetes.Publisher{Client: client, Names: names},
		Discoverer: pkikubernetes.Discoverer{Client: client, Names: names},
		Verifier:   verifier, Issuer: issuer,
	}
	recoverer := pkikubernetes.Recoverer{Client: client, Store: store, Locker: locker, Issuer: issuer, Names: names}
	return ReconcilerRuntime{Store: store, Reconciler: reconciler, Verifier: verifier, RecoverFunc: recoverer.Recover}, nil
}

func selectorFromMap(selector map[string]string) string {
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
