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
)

const APIVersion = rotation.StateSchemaVersion

// File is the versioned YAML document accepted by every CLI command.
type File struct {
	APIVersion               string  `yaml:"apiVersion" json:"apiVersion"`
	Namespace                string  `yaml:"namespace" json:"namespace"`
	AcknowledgementNamespace string  `yaml:"acknowledgementNamespace,omitempty" json:"acknowledgementNamespace,omitempty"`
	Webhook                  Webhook `yaml:"webhook" json:"webhook"`
	MTLS                     MTLS    `yaml:"mtls" json:"mtls"`
	Policy                   Policy  `yaml:"policy" json:"policy"`
}

// Webhook preserves the existing Zeist admission output contract.
type Webhook struct {
	Service             string   `yaml:"service" json:"service"`
	Secret              string   `yaml:"secret" json:"secret"`
	CanaryService       string   `yaml:"canaryService" json:"canaryService"`
	CanarySecret        string   `yaml:"canarySecret" json:"canarySecret"`
	CanaryConfiguration string   `yaml:"canaryConfiguration" json:"canaryConfiguration"`
	APIServerEndpoints  []string `yaml:"apiServerEndpoints,omitempty" json:"apiServerEndpoints,omitempty"`
}

// MTLS preserves the existing Zeist runner output contract.
type MTLS struct {
	ServerSecret string            `yaml:"serverSecret" json:"serverSecret"`
	ClientSecret string            `yaml:"clientSecret" json:"clientSecret"`
	NodeSelector map[string]string `yaml:"nodeSelector" json:"nodeSelector"`
	Port         int32             `yaml:"port" json:"port"`
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
	if f.Webhook.Service == "" || f.Webhook.Secret == "" || f.Webhook.CanaryService == "" || f.Webhook.CanarySecret == "" || f.Webhook.CanaryConfiguration == "" {
		return fmt.Errorf("webhook service, secret, canaryService, canarySecret, and canaryConfiguration are required")
	}
	for _, endpoint := range f.Webhook.APIServerEndpoints {
		parsed, err := url.ParseRequestURI(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.RawPath != "" {
			return fmt.Errorf("webhook apiServerEndpoints must contain absolute HTTPS origins")
		}
	}
	if f.MTLS.ServerSecret == "" || f.MTLS.ClientSecret == "" || len(f.MTLS.NodeSelector) == 0 || f.MTLS.Port <= 0 || f.MTLS.Port > 65535 {
		return fmt.Errorf("mtls serverSecret, clientSecret, nodeSelector, and valid port are required")
	}
	_, err := f.RotationPolicy()
	return err
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

// Domains returns the fixed v0.1 trust-domain set, each independently rooted.
func (f File) Domains() ([]rotation.Domain, error) {
	policy, err := f.RotationPolicy()
	if err != nil {
		return nil, err
	}
	return []rotation.Domain{
		{Name: "webhook", Profile: rotation.ProfileWebhook, ConfigurationHash: f.DomainHash("webhook"), Policy: policy},
		{Name: "mtls", Profile: rotation.ProfileMTLS, ConfigurationHash: f.DomainHash("mtls"), Policy: policy},
	}, nil
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
		keys := make([]string, 0, len(f.MTLS.NodeSelector))
		for key := range f.MTLS.NodeSelector {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			parts = append(parts, key, f.MTLS.NodeSelector[key])
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
