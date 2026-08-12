package kubernetes

import (
	"context"
	"fmt"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// publishWebhookTrust updates only the explicitly named production and canary
// webhook configurations. Restricting this integration to known names avoids
// a broad list-and-mutate permission over a cluster's admission boundary.
func (p Publisher) publishWebhookTrust(ctx context.Context, bundle, canaryBundle []byte) error {
	if len(bundle) == 0 || len(canaryBundle) == 0 {
		return fmt.Errorf("webhook publication has no production or canary trust bundle")
	}
	if err := p.requireWebhookCanary(); err != nil {
		return err
	}
	if len(p.Names.WebhookConfigurationNames) == 0 {
		return fmt.Errorf("at least one named production webhook configuration is required")
	}
	productionMatches := 0
	for _, name := range p.Names.WebhookConfigurationNames {
		matches, err := p.publishNamedWebhookTrust(ctx, name, p.Names.WebhookService, bundle)
		if err != nil {
			return err
		}
		productionMatches += matches
	}
	canaryMatches, err := p.publishNamedWebhookTrust(ctx, p.Names.WebhookCanaryConfiguration, p.Names.WebhookCanaryService, canaryBundle)
	if err != nil {
		return err
	}
	if productionMatches == 0 {
		return fmt.Errorf("no webhook configuration references Service %s/%s", p.Names.Namespace, p.Names.WebhookService)
	}
	if canaryMatches == 0 {
		return fmt.Errorf("webhook canary configuration %q does not reference Service %s/%s", p.Names.WebhookCanaryConfiguration, p.Names.Namespace, p.Names.WebhookCanaryService)
	}
	return nil
}

func (p Publisher) publishNamedWebhookTrust(ctx context.Context, name, service string, bundle []byte) (int, error) {
	matches := 0
	configuration, err := p.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		changed := setMutatingWebhookTrust(configuration, p.Names.Namespace, service, bundle)
		matches += countMutatingWebhookServices(configuration, p.Names.Namespace, service)
		if changed {
			if _, err := p.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Update(ctx, configuration, metav1.UpdateOptions{}); err != nil {
				return 0, fmt.Errorf("update mutating webhook configuration %q: %w", name, err)
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return 0, fmt.Errorf("get mutating webhook configuration %q: %w", name, err)
	}
	validating, err := p.Client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		changed := setValidatingWebhookTrust(validating, p.Names.Namespace, service, bundle)
		matches += countValidatingWebhookServices(validating, p.Names.Namespace, service)
		if changed {
			if _, err := p.Client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Update(ctx, validating, metav1.UpdateOptions{}); err != nil {
				return 0, fmt.Errorf("update validating webhook configuration %q: %w", name, err)
			}
		}
		return matches, nil
	}
	if !apierrors.IsNotFound(err) {
		return 0, fmt.Errorf("get configured webhook configuration %q: %w", name, err)
	}
	return matches, nil
}

func setMutatingWebhookTrust(configuration *admissionv1.MutatingWebhookConfiguration, namespace, service string, bundle []byte) bool {
	changed := false
	for index := range configuration.Webhooks {
		client := &configuration.Webhooks[index].ClientConfig
		if !webhookServiceMatches(client.Service, namespace, service) {
			continue
		}
		if string(client.CABundle) != string(bundle) {
			client.CABundle = append([]byte(nil), bundle...)
			changed = true
		}
	}
	return changed
}

func setValidatingWebhookTrust(configuration *admissionv1.ValidatingWebhookConfiguration, namespace, service string, bundle []byte) bool {
	changed := false
	for index := range configuration.Webhooks {
		client := &configuration.Webhooks[index].ClientConfig
		if !webhookServiceMatches(client.Service, namespace, service) {
			continue
		}
		if string(client.CABundle) != string(bundle) {
			client.CABundle = append([]byte(nil), bundle...)
			changed = true
		}
	}
	return changed
}

func countMutatingWebhookServices(configuration *admissionv1.MutatingWebhookConfiguration, namespace, service string) int {
	count := 0
	for _, webhook := range configuration.Webhooks {
		if webhookServiceMatches(webhook.ClientConfig.Service, namespace, service) {
			count++
		}
	}
	return count
}

func countValidatingWebhookServices(configuration *admissionv1.ValidatingWebhookConfiguration, namespace, service string) int {
	count := 0
	for _, webhook := range configuration.Webhooks {
		if webhookServiceMatches(webhook.ClientConfig.Service, namespace, service) {
			count++
		}
	}
	return count
}

func webhookServiceMatches(reference *admissionv1.ServiceReference, namespace, service string) bool {
	return reference != nil && reference.Namespace == namespace && reference.Name == service
}
