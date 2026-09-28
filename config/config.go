// Package config decodes the intentionally small zeist-pki CLI configuration.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zeisthq/zeist-pki/rotation"
	"gopkg.in/yaml.v3"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
)

const APIVersion = rotation.StateSchemaVersion

// File is the versioned YAML document accepted by every CLI command.
type File struct {
	APIVersion               string        `yaml:"apiVersion" json:"apiVersion"`
	Namespace                string        `yaml:"namespace" json:"namespace"`
	AcknowledgementNamespace string        `yaml:"acknowledgementNamespace,omitempty" json:"acknowledgementNamespace,omitempty"`
	Webhook                  Webhook       `yaml:"webhook" json:"webhook"`
	MTLS                     MTLS          `yaml:"mtls" json:"mtls"`
	ServiceMTLS              []ServiceMTLS `yaml:"serviceMTLS,omitempty" json:"serviceMTLS,omitempty"`
	Policy                   Policy        `yaml:"policy" json:"policy"`
}

// Webhook preserves the existing Zeist admission output contract.
type Webhook struct {
	Service             string            `yaml:"service" json:"service"`
	Secret              string            `yaml:"secret" json:"secret"`
	CanaryService       string            `yaml:"canaryService" json:"canaryService"`
	CanarySecret        string            `yaml:"canarySecret" json:"canarySecret"`
	CanaryConfiguration string            `yaml:"canaryConfiguration" json:"canaryConfiguration"`
	APIServerEndpoints  []string          `yaml:"apiServerEndpoints,omitempty" json:"apiServerEndpoints,omitempty"`
	PodSelector         map[string]string `yaml:"podSelector" json:"podSelector"`
	ConfigurationNames  []string          `yaml:"configurationNames" json:"configurationNames"`
	CanaryResourcePath  string            `yaml:"canaryResourcePath" json:"canaryResourcePath"`
	CanaryAnnotation    string            `yaml:"canaryAnnotation" json:"canaryAnnotation"`
}

// MTLS preserves the existing Zeist runner output contract.
type MTLS struct {
	ServerSecret      string            `yaml:"serverSecret" json:"serverSecret"`
	ClientSecret      string            `yaml:"clientSecret" json:"clientSecret"`
	Service           string            `yaml:"service" json:"service"`
	NodeSelector      map[string]string `yaml:"nodeSelector" json:"nodeSelector"`
	ClientPodSelector map[string]string `yaml:"clientPodSelector" json:"clientPodSelector"`
	ServerPodSelector map[string]string `yaml:"serverPodSelector" json:"serverPodSelector"`
	Port              int32             `yaml:"port" json:"port"`
}

// ServiceMTLS configures one independently rooted service relationship.
type ServiceMTLS struct {
	Name          string            `yaml:"name" json:"name"`
	ClusterDomain string            `yaml:"clusterDomain,omitempty" json:"clusterDomain,omitempty"`
	Server        ServiceMTLSServer `yaml:"server" json:"server"`
	Client        ServiceMTLSClient `yaml:"client" json:"client"`
}

// ServiceMTLSServer describes the serving identity and its exact consumers.
type ServiceMTLSServer struct {
	Namespace   string            `yaml:"namespace" json:"namespace"`
	Service     string            `yaml:"service" json:"service"`
	Secret      string            `yaml:"secret" json:"secret"`
	PodSelector map[string]string `yaml:"podSelector" json:"podSelector"`
	Port        int32             `yaml:"port" json:"port"`
	// ProbeOnly verifies every Ready host-network server directly when it has no API token for Lease acknowledgements.
	ProbeOnly bool `yaml:"probeOnly,omitempty" json:"probeOnly,omitempty"`
}

// ServiceMTLSClient describes the client identity and its exact consumers.
type ServiceMTLSClient struct {
	Namespace   string            `yaml:"namespace" json:"namespace"`
	Secret      string            `yaml:"secret" json:"secret"`
	PodSelector map[string]string `yaml:"podSelector" json:"podSelector"`
}

// Policy provides optional duration overrides. Empty fields use rotation's
// conservative defaults.
type Policy struct {
	RootValidity        string `yaml:"rootValidity" json:"rootValidity"`
	RootRolloverBefore  string `yaml:"rootRolloverBefore" json:"rootRolloverBefore"`
	LeafValidity        string `yaml:"leafValidity" json:"leafValidity"`
	LeafRenewBefore     string `yaml:"leafRenewBefore" json:"leafRenewBefore"`
	MinimumTrustOverlap string `yaml:"minimumTrustOverlap" json:"minimumTrustOverlap"`
	ClockSkew           string `yaml:"clockSkew" json:"clockSkew"`
}

// Load reads and validates a configuration file.
func Load(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("read config: %w", err)
	}
	return decodeAndValidate(data)
}

// decodeAndValidate decodes exactly one versioned configuration document.
// KnownFields is intentional: a misspelled lifecycle setting must never be
// accepted and silently replaced by a security-sensitive default.
func decodeAndValidate(data []byte) (File, error) {
	var file File
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		return File{}, fmt.Errorf("decode config: %w", err)
	}
	var additional any
	if err := decoder.Decode(&additional); err != io.EOF {
		if err == nil {
			return File{}, fmt.Errorf("decode config: multiple YAML documents are not supported")
		}
		return File{}, fmt.Errorf("decode config: %w", err)
	}
	if err := file.Validate(); err != nil {
		return File{}, err
	}
	return file, nil
}

// Validate rejects undeclared v0.1 surface rather than silently accepting
// a configuration that appears to offer a broader certificate API.
func (f File) Validate() error {
	if f.APIVersion != APIVersion {
		return fmt.Errorf("apiVersion must be %q", APIVersion)
	}
	if f.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}
	if errors := k8svalidation.IsDNS1123Label(f.Namespace); len(errors) != 0 {
		return fmt.Errorf("namespace is invalid: %s", strings.Join(errors, "; "))
	}
	if f.Webhook.Service == "" || f.Webhook.Secret == "" || f.Webhook.CanaryService == "" || f.Webhook.CanarySecret == "" || f.Webhook.CanaryConfiguration == "" ||
		len(f.Webhook.PodSelector) == 0 || len(f.Webhook.ConfigurationNames) == 0 || f.Webhook.CanaryResourcePath == "" || f.Webhook.CanaryAnnotation == "" {
		return fmt.Errorf("webhook outputs, podSelector, configurationNames, canaryResourcePath, and canaryAnnotation are required")
	}
	if err := validateCanaryPath(f.Webhook.CanaryResourcePath); err != nil {
		return err
	}
	if errors := k8svalidation.IsQualifiedName(f.Webhook.CanaryAnnotation); len(errors) != 0 {
		return fmt.Errorf("webhook canaryAnnotation is invalid: %s", strings.Join(errors, "; "))
	}
	if err := validateSelector("webhook podSelector", f.Webhook.PodSelector); err != nil {
		return err
	}
	for _, name := range f.Webhook.ConfigurationNames {
		if errors := k8svalidation.IsDNS1123Subdomain(name); len(errors) != 0 {
			return fmt.Errorf("webhook configurationNames contains invalid name %q: %s", name, strings.Join(errors, "; "))
		}
	}
	for _, endpoint := range f.Webhook.APIServerEndpoints {
		parsed, err := url.ParseRequestURI(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.RawPath != "" {
			return fmt.Errorf("webhook apiServerEndpoints must contain absolute HTTPS origins")
		}
	}
	if f.MTLS.ServerSecret == "" || f.MTLS.ClientSecret == "" || f.MTLS.Service == "" || len(f.MTLS.NodeSelector) == 0 ||
		len(f.MTLS.ClientPodSelector) == 0 || len(f.MTLS.ServerPodSelector) == 0 || f.MTLS.Port <= 0 || f.MTLS.Port > 65535 {
		return fmt.Errorf("mtls outputs, service, selectors, and valid port are required")
	}
	for label, selector := range map[string]map[string]string{
		"mtls nodeSelector": f.MTLS.NodeSelector, "mtls clientPodSelector": f.MTLS.ClientPodSelector, "mtls serverPodSelector": f.MTLS.ServerPodSelector,
	} {
		if err := validateSelector(label, selector); err != nil {
			return err
		}
	}
	seenDomains := map[string]struct{}{"webhook": {}, "mtls": {}}
	for index, service := range f.ServiceMTLS {
		if err := service.Validate(); err != nil {
			return fmt.Errorf("serviceMTLS[%d]: %w", index, err)
		}
		if _, duplicate := seenDomains[service.Name]; duplicate {
			return fmt.Errorf("serviceMTLS domain %q is duplicated or reserved", service.Name)
		}
		seenDomains[service.Name] = struct{}{}
	}
	_, err := f.RotationPolicy()
	return err
}

func validateCanaryPath(value string) error {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || !strings.HasPrefix(parsed.Path, "/apis/") || parsed.RawQuery != "" || parsed.Fragment != "" || strings.HasSuffix(parsed.Path, "/") {
		return fmt.Errorf("webhook canaryResourcePath must be an absolute Kubernetes API resource path")
	}
	return nil
}

// Validate checks one generic service-mTLS relationship.
func (s ServiceMTLS) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(s.Name) > 32 {
		return fmt.Errorf("name must contain at most 32 characters so its Lease names remain valid")
	}
	if errors := k8svalidation.IsDNS1123Label(s.Name); len(errors) != 0 {
		return fmt.Errorf("name must be a DNS-compatible trust-domain identifier: %s", strings.Join(errors, "; "))
	}
	if s.Server.Namespace == "" || s.Server.Service == "" || s.Server.Secret == "" || len(s.Server.PodSelector) == 0 || s.Server.Port <= 0 || s.Server.Port > 65535 {
		return fmt.Errorf("server namespace, service, secret, podSelector, and valid port are required")
	}
	if s.Client.Namespace == "" || s.Client.Secret == "" || len(s.Client.PodSelector) == 0 {
		return fmt.Errorf("client namespace, secret, and podSelector are required")
	}
	if s.Server.Namespace == s.Client.Namespace && s.Server.Secret == s.Client.Secret {
		return fmt.Errorf("server and client Secrets must be different")
	}
	for label, value := range map[string]string{
		"server namespace": s.Server.Namespace, "server service": s.Server.Service, "client namespace": s.Client.Namespace,
	} {
		if errors := k8svalidation.IsDNS1123Label(value); len(errors) != 0 {
			return fmt.Errorf("%s is invalid: %s", label, strings.Join(errors, "; "))
		}
	}
	for label, value := range map[string]string{"server secret": s.Server.Secret, "client secret": s.Client.Secret} {
		if errors := k8svalidation.IsDNS1123Subdomain(value); len(errors) != 0 {
			return fmt.Errorf("%s is invalid: %s", label, strings.Join(errors, "; "))
		}
	}
	if err := validateSelector("server podSelector", s.Server.PodSelector); err != nil {
		return err
	}
	if err := validateSelector("client podSelector", s.Client.PodSelector); err != nil {
		return err
	}
	if strings.Trim(s.ClusterDomain, ".") == "" && s.ClusterDomain != "" {
		return fmt.Errorf("clusterDomain is invalid")
	}
	if clusterDomain := strings.Trim(s.ClusterDomain, "."); clusterDomain != "" {
		if errors := k8svalidation.IsDNS1123Subdomain(clusterDomain); len(errors) != 0 {
			return fmt.Errorf("clusterDomain is invalid: %s", strings.Join(errors, "; "))
		}
	}
	return nil
}

func validateSelector(name string, selector map[string]string) error {
	for key, value := range selector {
		if errors := k8svalidation.IsQualifiedName(key); len(errors) != 0 {
			return fmt.Errorf("%s contains invalid key %q: %s", name, key, strings.Join(errors, "; "))
		}
		if errors := k8svalidation.IsValidLabelValue(value); len(errors) != 0 {
			return fmt.Errorf("%s contains invalid value for %q: %s", name, key, strings.Join(errors, "; "))
		}
	}
	return nil
}

// EffectiveClusterDomain returns the DNS suffix used for long Service names.
func (s ServiceMTLS) EffectiveClusterDomain() string {
	if s.ClusterDomain == "" {
		return "cluster.local"
	}
	return strings.Trim(s.ClusterDomain, ".")
}

// AcknowledgementsNamespace returns the isolated namespace used for consumer
// proof Leases. Empty configuration preserves portability by using Namespace.
func (f File) AcknowledgementsNamespace() string {
	if f.AcknowledgementNamespace != "" {
		return f.AcknowledgementNamespace
	}
	return f.Namespace
}

// RotationPolicy parses only explicit duration overrides.
func (f File) RotationPolicy() (rotation.Policy, error) {
	p := rotation.DefaultPolicy()
	for _, item := range []struct {
		text string
		set  func(time.Duration)
	}{
		{f.Policy.RootValidity, func(value time.Duration) { p.RootValidity = value }},
		{f.Policy.RootRolloverBefore, func(value time.Duration) { p.RootRolloverBefore = value }},
		{f.Policy.LeafValidity, func(value time.Duration) { p.LeafValidity = value }},
		{f.Policy.LeafRenewBefore, func(value time.Duration) { p.LeafRenewBefore = value }},
		{f.Policy.MinimumTrustOverlap, func(value time.Duration) { p.MinimumTrustOverlap = value }},
		{f.Policy.ClockSkew, func(value time.Duration) { p.ClockSkew = value }},
	} {
		if item.text == "" {
			continue
		}
		value, err := time.ParseDuration(item.text)
		if err != nil {
			return rotation.Policy{}, fmt.Errorf("parse policy duration %q: %w", item.text, err)
		}
		item.set(value)
	}
	if err := p.Validate(); err != nil {
		return rotation.Policy{}, err
	}
	return p, nil
}

// Domains returns every independently rooted trust domain.
func (f File) Domains() ([]rotation.Domain, error) {
	policy, err := f.RotationPolicy()
	if err != nil {
		return nil, err
	}
	domains := []rotation.Domain{
		{Name: "webhook", Profile: rotation.ProfileWebhook, ConfigurationHash: f.DomainHash("webhook"), Policy: policy, Metadata: map[string]string{"bindingHash": f.BindingHash("webhook")}},
		{Name: "mtls", Profile: rotation.ProfileMTLS, ConfigurationHash: f.DomainHash("mtls"), Policy: policy, Metadata: map[string]string{"bindingHash": f.BindingHash("mtls")}},
	}
	services := append([]ServiceMTLS(nil), f.ServiceMTLS...)
	sort.Slice(services, func(first, second int) bool { return services[first].Name < services[second].Name })
	for _, service := range services {
		domains = append(domains, rotation.Domain{
			Name: service.Name, Profile: rotation.ProfileServiceMTLS, ConfigurationHash: f.DomainHash(service.Name), Policy: policy,
			Metadata: map[string]string{"bindingHash": f.BindingHash(service.Name)},
		})
	}
	return domains, nil
}

// DomainHash is stable across YAML formatting and includes the domain-specific
// output shape, not any secret value.
func (f File) DomainHash(domain string) string {
	parts := []string{APIVersion, f.Namespace, f.AcknowledgementsNamespace(), domain}
	switch domain {
	case "webhook":
		parts = append(parts, f.Webhook.Service, f.Webhook.Secret, f.Webhook.CanaryService, f.Webhook.CanarySecret, f.Webhook.CanaryConfiguration)
		endpoints := append([]string(nil), f.Webhook.APIServerEndpoints...)
		sort.Strings(endpoints)
		parts = append(parts, endpoints...)
	case "mtls":
		parts = append(parts, f.MTLS.ServerSecret, f.MTLS.ClientSecret, fmt.Sprintf("%d", f.MTLS.Port))
		parts = appendSelector(parts, f.MTLS.NodeSelector)
	default:
		if service, found := f.ServiceMTLSDomain(domain); found {
			parts = append(parts,
				service.EffectiveClusterDomain(),
				service.Server.Namespace, service.Server.Service, service.Server.Secret, fmt.Sprintf("%d", service.Server.Port),
			)
			// Preserve hashes for existing domains that did not opt into direct probes.
			if service.Server.ProbeOnly {
				parts = append(parts, "true")
			}
			parts = append(parts, service.Client.Namespace, service.Client.Secret)
			parts = appendSelector(parts, service.Server.PodSelector)
			parts = appendSelector(parts, service.Client.PodSelector)
		}
	}
	policy, _ := f.RotationPolicy()
	parts = append(parts,
		policy.RootValidity.String(), policy.RootRolloverBefore.String(), policy.LeafValidity.String(),
		policy.LeafRenewBefore.String(), policy.MinimumTrustOverlap.String(), policy.ClockSkew.String(),
	)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BindingHash identifies discovery and probe bindings that legacy state hashes
// did not include. Persisted target snapshots use this value to force safe
// republishing when an operator changes a selector or endpoint.
func (f File) BindingHash(domain string) string {
	parts := []string{domain}
	switch domain {
	case "webhook":
		parts = append(parts, f.Webhook.Service, f.Webhook.Secret, f.Webhook.CanaryService, f.Webhook.CanarySecret, f.Webhook.CanaryConfiguration, f.Webhook.CanaryResourcePath, f.Webhook.CanaryAnnotation)
		configurationNames := append([]string(nil), f.Webhook.ConfigurationNames...)
		sort.Strings(configurationNames)
		parts = append(parts, configurationNames...)
		parts = appendSelector(parts, f.Webhook.PodSelector)
	case "mtls":
		parts = append(parts, f.MTLS.Service, f.MTLS.ServerSecret, f.MTLS.ClientSecret, fmt.Sprintf("%d", f.MTLS.Port))
		parts = appendSelector(parts, f.MTLS.NodeSelector)
		parts = appendSelector(parts, f.MTLS.ClientPodSelector)
		parts = appendSelector(parts, f.MTLS.ServerPodSelector)
	default:
		if service, found := f.ServiceMTLSDomain(domain); found {
			parts = append(parts, f.DomainHash(domain))
			parts = appendSelector(parts, service.Server.PodSelector)
			parts = appendSelector(parts, service.Client.PodSelector)
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ServiceMTLSDomain returns one configured generic relationship by name.
func (f File) ServiceMTLSDomain(name string) (ServiceMTLS, bool) {
	for _, service := range f.ServiceMTLS {
		if service.Name == name {
			return service, true
		}
	}
	return ServiceMTLS{}, false
}

func appendSelector(parts []string, selector map[string]string) []string {
	keys := make([]string, 0, len(selector))
	for key := range selector {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, key, selector[key])
	}
	return parts
}
