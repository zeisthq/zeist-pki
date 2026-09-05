// zeist-pki is the command-line entry point for the small private-PKI
// lifecycle manager. It intentionally exposes only the fixed v0.1 command
// surface; the configuration file is not a Kubernetes API.
package main

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zeisthq/zeist-pki/config"
	"github.com/zeisthq/zeist-pki/rotation"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	defaultRunInterval = 5 * time.Minute
	maxRunJitter       = 30 * time.Second
)

var errHelpRequested = errors.New("help requested")

type commandOptions struct {
	name          string
	configPath    string
	kubeconfig    string
	output        string
	offline       bool
	domains       []string
	confirmations []string
}

// app keeps command dependencies injectable for unit tests. Production uses
// the concrete Kubernetes integration; offline planning remains deliberately
// read-only rather than guessing at an issuer or credentials.
type app struct {
	factory  RuntimeFactory
	interval time.Duration
	jitter   func(time.Duration) time.Duration
}

func defaultApp() app {
	return app{
		factory:  kubernetesRuntimeFactory{},
		interval: defaultRunInterval,
		jitter:   runJitter,
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := defaultApp().execute(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "zeist-pki:", err)
		os.Exit(1)
	}
}

func (a app) execute(ctx context.Context, arguments []string, output io.Writer) error {
	options, err := parseCommand(arguments)
	if errors.Is(err, errHelpRequested) {
		writeUsage(output)
		return nil
	}
	if err != nil {
		return err
	}

	file, err := config.Load(options.configPath)
	if err != nil {
		return err
	}
	domains, err := file.Domains()
	if err != nil {
		return fmt.Errorf("derive trust domains: %w", err)
	}
	if options.name == "apply" && len(options.domains) != 0 {
		domains, err = selectConfiguredDomains("apply", options.domains, domains)
		if err != nil {
			return err
		}
	}
	var recoveryDomains []rotation.Domain
	var recoveryConfirmations map[string]string
	if options.name == "recover" {
		recoveryDomains, err = selectRecoveryDomains(options.domains, domains)
		if err != nil {
			return err
		}
		recoveryConfirmations, err = confirmationsForDomains(options.confirmations, recoveryDomains)
		if err != nil {
			return err
		}
	}
	factory := a.factory
	if factory == nil {
		return fmt.Errorf("runtime factory is required")
	}
	var runtime Runtime
	if options.offline {
		runtime = offlinePlanRuntime{}
	} else {
		clientConfig, configErr := buildRESTConfig(options.kubeconfig)
		if configErr != nil && options.name == "plan" {
			// A fresh-domain plan is valuable in CI and documentation generation;
			// it remains fully read-only and simply reports bootstrap when there is
			// no Kubernetes credential source from which to inspect existing state.
			runtime = offlinePlanRuntime{}
		} else {
			if configErr != nil {
				return configErr
			}
			runtime, err = factory.Build(ctx, RuntimeOptions{
				Config: file, RESTConfig: clientConfig, Identity: runtimeIdentity(),
			})
			if err != nil {
				return err
			}
		}
	}

	switch options.name {
	case "plan":
		plans, err := plansForDomains(ctx, runtime, domains)
		if err != nil {
			return err
		}
		return writeCommandOutput(output, options.output, planOutput{Plans: plans})
	case "apply":
		results, err := applyDomains(ctx, runtime, domains)
		if err != nil {
			return err
		}
		return writeCommandOutput(output, options.output, applyOutput{Results: results})
	case "run":
		return a.run(ctx, runtime, domains, options.output, output)
	case "status":
		statuses, err := statusesForDomains(ctx, runtime, domains)
		if err != nil {
			return err
		}
		return writeCommandOutput(output, options.output, statusOutput{Domains: statuses})
	case "verify":
		results, err := verifyDomains(ctx, runtime, domains)
		if err != nil {
			return err
		}
		return writeCommandOutput(output, options.output, verifyOutput{Results: results})
	case "recover":
		results, err := recoverDomains(ctx, runtime, recoveryDomains, recoveryConfirmations)
		if err != nil {
			return err
		}
		return writeCommandOutput(output, options.output, recoverOutput{Results: results})
	default:
		return fmt.Errorf("unsupported command %q", options.name)
	}
}

func parseCommand(arguments []string) (commandOptions, error) {
	if len(arguments) == 0 || arguments[0] == "help" || arguments[0] == "--help" || arguments[0] == "-h" {
		return commandOptions{}, errHelpRequested
	}
	options := commandOptions{name: arguments[0]}
	switch options.name {
	case "plan", "apply", "run", "status", "verify", "recover":
	default:
		return commandOptions{}, fmt.Errorf("unknown command %q", options.name)
	}

	flags := flag.NewFlagSet(options.name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.configPath, "config", "", "path to versioned YAML configuration")
	flags.StringVar(&options.kubeconfig, "kubeconfig", "", "optional kubeconfig fallback path")
	flags.StringVar(&options.output, "output", "text", "output format: text or json")
	flags.BoolVar(&options.offline, "offline", false, "plan without reading Kubernetes state")
	flags.Var((*domainValues)(&options.domains), "domain", "configured trust domain to apply or recover; repeat to select more than one")
	flags.Var((*stringValues)(&options.confirmations), "confirm-active-root-fingerprint", "domain=fingerprint confirmation; repeat once per selected recovery domain")
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return commandOptions{}, errHelpRequested
		}
		return commandOptions{}, err
	}
	if len(flags.Args()) > 0 {
		return commandOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if options.configPath == "" {
		return commandOptions{}, fmt.Errorf("--config is required")
	}
	if options.output != "text" && options.output != "json" {
		return commandOptions{}, fmt.Errorf("--output must be text or json")
	}
	if options.name == "recover" {
		if len(options.domains) == 0 {
			return commandOptions{}, fmt.Errorf("recover requires at least one --domain")
		}
		if len(options.confirmations) == 0 {
			return commandOptions{}, fmt.Errorf("recover requires --confirm-active-root-fingerprint for every selected domain")
		}
	} else if options.name != "apply" && len(options.domains) != 0 {
		if options.name == "run" {
			return commandOptions{}, fmt.Errorf("run always reconciles every configured domain and does not accept --domain")
		}
		return commandOptions{}, fmt.Errorf("--domain is supported only by apply and recover")
	}
	if options.offline && options.name != "plan" {
		return commandOptions{}, fmt.Errorf("--offline is supported only by plan")
	}
	return options, nil
}

type stringValues []string

func (values *stringValues) String() string { return strings.Join(*values, ",") }

func (values *stringValues) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("fingerprint confirmation cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

type domainValues []string

func (values *domainValues) String() string { return strings.Join(*values, ",") }

func (values *domainValues) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

func buildRESTConfig(kubeconfig string) (*rest.Config, error) {
	if inCluster, err := rest.InClusterConfig(); err == nil {
		return inCluster, nil
	}
	if kubeconfig == "" {
		defaultPath := clientcmd.RecommendedHomeFile
		if _, err := os.Stat(defaultPath); err != nil {
			return nil, fmt.Errorf("load Kubernetes configuration: in-cluster configuration is unavailable and no kubeconfig was found (pass --kubeconfig): %w", err)
		}
		kubeconfig = defaultPath
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes configuration: in-cluster configuration is unavailable and kubeconfig fallback failed: %w", err)
	}
	return config, nil
}

func runtimeIdentity() string {
	podUID := strings.TrimSpace(os.Getenv("ZEIST_PKI_POD_UID"))
	if podUID == "" {
		podUID = strings.TrimSpace(os.Getenv("POD_UID"))
	}
	base := ""
	if podUID != "" {
		base = "pod:" + podUID
	}
	if base == "" {
		hostname, err := os.Hostname()
		if err != nil || hostname == "" {
			hostname = "zeist-pki"
		}
		base = hostname
	}
	var suffix [8]byte
	if _, err := cryptorand.Read(suffix[:]); err == nil {
		return fmt.Sprintf("%s-%d-%s", base, os.Getpid(), hex.EncodeToString(suffix[:]))
	}
	return fmt.Sprintf("%s-%d-%d", base, os.Getpid(), time.Now().UnixNano())
}

func plansForDomains(ctx context.Context, runtime Runtime, domains []rotation.Domain) ([]rotation.Plan, error) {
	plans := make([]rotation.Plan, 0, len(domains))
	for _, domain := range domains {
		loaded, err := runtime.Load(ctx, domain.Name)
		var state *rotation.State
		switch {
		case err == nil:
			state = &loaded.State
		case errors.Is(err, rotation.ErrStateNotFound):
			// A nil state is intentionally a read-only bootstrap preview.
		default:
			return nil, fmt.Errorf("load %q state for plan: %w", domain.Name, err)
		}
		plan, err := rotation.PlanAt(domain, state, time.Now().UTC())
		if err != nil {
			return nil, fmt.Errorf("plan %q: %w", domain.Name, err)
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

func applyDomains(ctx context.Context, runtime Runtime, domains []rotation.Domain) ([]reconciliationSummary, error) {
	results := make([]reconciliationSummary, 0, len(domains))
	for _, domain := range domains {
		result, err := runtime.Apply(ctx, domain)
		if err != nil {
			return nil, &applyDomainError{domain: domain.Name, err: err}
		}
		results = append(results, summarizeResult(domain.Name, result))
	}
	return results, nil
}

// applyDomainError retains the affected configured trust domain without
// needing to serialize an arbitrary adapter error into a long-running command
// output stream. Adapter errors may originate from an API server or crypto
// parser and are intentionally not considered safe command-output data.
type applyDomainError struct {
	domain string
	err    error
}

func (err *applyDomainError) Error() string {
	return fmt.Sprintf("apply %q: %v", err.domain, err.err)
}

func (err *applyDomainError) Unwrap() error {
	return err.err
}

// runDomains reconciles every independently configured trust domain once. A
// long-running runner must not let a transient failure in one domain prevent
// renewal in another domain with a separate root and lifecycle state. Adapter
// error text stays inside the process; the returned failures are deliberately
// sanitized for streaming CLI output.
func runDomains(ctx context.Context, runtime Runtime, domains []rotation.Domain) ([]reconciliationSummary, []runFailure, error) {
	results := make([]reconciliationSummary, 0, len(domains))
	failures := make([]runFailure, 0)
	for _, domain := range domains {
		result, err := runtime.Apply(ctx, domain)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			failures = append(failures, runFailure{Domain: domain.Name, Message: "reconciliation failed"})
			continue
		}
		results = append(results, summarizeResult(domain.Name, result))
	}
	return results, failures, nil
}

func (a app) run(ctx context.Context, runtime Runtime, domains []rotation.Domain, format string, output io.Writer) error {
	interval := a.interval
	if interval <= 0 {
		interval = defaultRunInterval
	}
	jitter := a.jitter
	if jitter == nil {
		jitter = runJitter
	}
	for {
		results, failures, err := runDomains(ctx, runtime, domains)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if err := writeCommandOutput(output, format, runOutput{At: time.Now().UTC(), Results: results, Failures: failures}); err != nil {
			return err
		}

		delay := jitter(interval)
		if delay < interval {
			delay = interval
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil
		case <-timer.C:
		}
	}
}

func runJitter(interval time.Duration) time.Duration {
	if interval <= 0 {
		return interval
	}
	var bytes [2]byte
	if _, err := cryptorand.Read(bytes[:]); err != nil {
		return interval + maxRunJitter/2
	}
	additional := time.Duration((uint16(bytes[0])<<8|uint16(bytes[1]))%uint16(maxRunJitter/time.Millisecond+1)) * time.Millisecond
	return interval + additional
}

func statusesForDomains(ctx context.Context, runtime Runtime, domains []rotation.Domain) ([]domainStatus, error) {
	statuses := make([]domainStatus, 0, len(domains))
	for _, domain := range domains {
		loaded, err := runtime.Load(ctx, domain.Name)
		if errors.Is(err, rotation.ErrStateNotFound) {
			plan, planErr := rotation.PlanAt(domain, nil, time.Now().UTC())
			if planErr != nil {
				return nil, planErr
			}
			statuses = append(statuses, domainStatus{
				Domain: domain.Name, Health: "uninitialized", NextActions: plan.Actions,
			})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("load %q state for status: %w", domain.Name, err)
		}
		plan, err := rotation.PlanAt(domain, &loaded.State, time.Now().UTC())
		if err != nil {
			return nil, fmt.Errorf("plan %q status: %w", domain.Name, err)
		}
		statuses = append(statuses, summarizeStatus(domain.Name, loaded.State, plan))
	}
	return statuses, nil
}

func verifyDomains(ctx context.Context, runtime Runtime, domains []rotation.Domain) ([]verificationSummary, error) {
	results := make([]verificationSummary, 0, len(domains))
	for _, domain := range domains {
		loaded, err := runtime.Load(ctx, domain.Name)
		if errors.Is(err, rotation.ErrStateNotFound) {
			return nil, fmt.Errorf("verify %q: no persisted state", domain.Name)
		}
		if err != nil {
			return nil, fmt.Errorf("load %q state for verification: %w", domain.Name, err)
		}
		state := loaded.State
		if state.PublishedGeneration == 0 || len(state.PublishedMaterials) == 0 {
			return nil, fmt.Errorf("verify %q: no published generation", domain.Name)
		}
		publication := rotation.Publication{
			Domain: domain.Name, Generation: state.PublishedGeneration, OperationID: state.OperationID,
			Materials: state.PublishedMaterials, LeafNotAfter: state.LeafNotAfter, DualTrust: state.PublishedDualTrust,
		}
		request := rotation.VerificationRequest{
			Domain: domain, Generation: state.PublishedGeneration, OperationID: state.OperationID,
			Targets: state.Targets, Publication: publication,
		}
		acknowledgements, err := runtime.Verify(ctx, request)
		if err != nil {
			return nil, fmt.Errorf("verify %q generation %d: %w", domain.Name, state.PublishedGeneration, err)
		}
		if !acknowledgesEveryTarget(request.Targets, acknowledgements, publication) {
			return nil, fmt.Errorf("verify %q generation %d: incomplete acknowledgement evidence", domain.Name, state.PublishedGeneration)
		}
		results = append(results, verificationSummary{
			Domain: domain.Name, Generation: state.PublishedGeneration, Acknowledgements: len(acknowledgements), Verified: true,
		})
	}
	return results, nil
}

func acknowledgesEveryTarget(targets []rotation.Target, acknowledgements []rotation.Acknowledgement, publication rotation.Publication) bool {
	if len(targets) == 0 {
		return false
	}
	byTarget := make(map[string]rotation.Acknowledgement, len(acknowledgements))
	for _, acknowledgement := range acknowledgements {
		if acknowledgement.Generation == publication.Generation && acknowledgement.TargetID != "" {
			byTarget[acknowledgement.TargetID] = acknowledgement
		}
	}
	for _, target := range targets {
		expected, found := publication.MaterialFor(target)
		acknowledgement, acknowledged := byTarget[target.ID]
		if !found || !acknowledged || acknowledgement.LeafFingerprint != expected.LeafFingerprint || acknowledgement.TrustFingerprint != expected.TrustFingerprint {
			return false
		}
	}
	return true
}

func recoverDomains(ctx context.Context, runtime Runtime, domains []rotation.Domain, confirmations map[string]string) ([]reconciliationSummary, error) {
	results := make([]reconciliationSummary, 0, len(domains))
	for _, domain := range domains {
		result, err := runtime.Recover(ctx, domain, confirmations[domain.Name])
		if err != nil {
			return nil, fmt.Errorf("recover %q: %w", domain.Name, err)
		}
		results = append(results, summarizeResult(domain.Name, result))
	}
	return results, nil
}

// selectRecoveryDomains limits a guarded recovery to explicitly named fixed
// trust domains. The configured order makes a repeated multi-domain invocation
// deterministic, while each domain remains independently recoverable.
func selectRecoveryDomains(values []string, configured []rotation.Domain) ([]rotation.Domain, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("recover requires at least one --domain")
	}
	return selectConfiguredDomains("recover", values, configured)
}

// selectConfiguredDomains validates an explicit subset against the complete
// configuration, then returns it in the configuration's canonical order. The
// caller still loads and validates the whole configuration before selection;
// selection limits only the domains mutated by the requested operation.
func selectConfiguredDomains(operation string, values []string, configured []rotation.Domain) ([]rotation.Domain, error) {
	known := make(map[string]struct{}, len(configured))
	for _, domain := range configured {
		known[domain.Name] = struct{}{}
	}
	requested := make(map[string]struct{}, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value)
		if _, found := known[name]; !found {
			return nil, fmt.Errorf("%s names unknown configured domain %q", operation, name)
		}
		if _, duplicate := requested[name]; duplicate {
			return nil, fmt.Errorf("duplicate %s domain %q", operation, name)
		}
		requested[name] = struct{}{}
	}
	selected := make([]rotation.Domain, 0, len(requested))
	for _, domain := range configured {
		if _, found := requested[domain.Name]; found {
			selected = append(selected, domain)
		}
	}
	return selected, nil
}

func confirmationsForDomains(values []string, domains []rotation.Domain) (map[string]string, error) {
	selected := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		selected[domain.Name] = struct{}{}
	}
	confirmations := make(map[string]string, len(values))
	for _, value := range values {
		parts := strings.SplitN(value, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, fmt.Errorf("--confirm-active-root-fingerprint must use domain=fingerprint")
		}
		domain, fingerprint := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if _, duplicate := confirmations[domain]; duplicate {
			return nil, fmt.Errorf("duplicate active-root confirmation for %q", domain)
		}
		if _, found := selected[domain]; !found {
			return nil, fmt.Errorf("active-root confirmation names unselected recovery domain %q", domain)
		}
		confirmations[domain] = fingerprint
	}
	for _, domain := range domains {
		if confirmations[domain.Name] == "" {
			return nil, fmt.Errorf("recover requires --confirm-active-root-fingerprint %s=<fingerprint>", domain.Name)
		}
	}
	if len(confirmations) != len(domains) {
		return nil, fmt.Errorf("active-root confirmations name an unknown trust domain")
	}
	return confirmations, nil
}

func writeUsage(output io.Writer) {
	fmt.Fprint(output, `zeist-pki is a small private PKI lifecycle manager for cloud-native systems.

Usage:
  zeist-pki <command> --config <path> [--kubeconfig <path>] [--output text|json]

Commands:
  plan      Preview deterministic lifecycle actions without generating keys or writing state.
  apply     Run one bounded reconciliation for each configured trust domain.
  run       Reconcile immediately, then every five minutes with jitter until interrupted.
  status    Report credential-free health, expiry, phase, generations, and blockers.
  verify    Run configured live activation verification for published generations.
  recover   Guardedly adopt surviving outputs after exact root-fingerprint confirmation.

Recover requires one confirmation per selected domain:
  zeist-pki recover --config pki.yaml --domain webhook \
    --confirm-active-root-fingerprint webhook=<fingerprint>

Repeat both flags to recover another selected domain. Domains not named by
--domain are not read or modified by recover.

Apply reconciles every configured domain by default. Repeat --domain to apply
only an exact configured subset; selected domains run in canonical config
order. Run deliberately does not accept --domain and always reconciles all
configured domains.
`)
}
