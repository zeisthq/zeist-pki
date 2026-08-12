package kubernetes

import (
	"testing"
	"time"

	"github.com/zeisthq/zeist-pki/pki"
)

func TestVerifyWebhookPeerFingerprint(t *testing.T) {
	now := time.Now().UTC()
	root, err := pki.IssueRoot(pki.RootOptions{CommonName: "root", Validity: 365 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.IssueLeaf(root, pki.LeafOptions{
		CommonName: "manager.system.svc", Profile: pki.ProfileWebhook,
		DNSNames: []string{"manager.system.svc"}, Validity: 24 * time.Hour, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyWebhookPeerFingerprint([][]byte{leaf.Certificate.Raw}, certificateFingerprint(leaf.Certificate)); err != nil {
		t.Fatalf("matching webhook peer: %v", err)
	}
	if err := verifyWebhookPeerFingerprint([][]byte{leaf.Certificate.Raw}, "sha256:wrong"); err == nil {
		t.Fatal("accepted an old or unexpected webhook peer leaf")
	}
	if err := verifyWebhookPeerFingerprint(nil, certificateFingerprint(leaf.Certificate)); err == nil {
		t.Fatal("accepted an empty webhook peer chain")
	}
}
