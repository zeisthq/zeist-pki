// Package main is a portable, in-memory example for the pki package.
package main

import (
	"crypto/x509"
	"fmt"
	"log"

	"github.com/zeisthq/zeist-pki/pki"
)

func main() {
	root, err := pki.IssueRoot(pki.RootOptions{
		CommonName: "example platform root",
	})
	if err != nil {
		log.Fatalf("issue root: %v", err)
	}

	leaf, err := pki.IssueLeaf(root, pki.LeafOptions{
		CommonName: "api.example.test",
		Profile:    pki.ProfileServer,
		DNSNames:   []string{"api.example.test"},
	})
	if err != nil {
		log.Fatalf("issue server leaf: %v", err)
	}
	if err := pki.ValidateLeaf(leaf, []*x509.Certificate{root.Certificate}, pki.ProfileServer, leaf.Certificate.NotBefore); err != nil {
		log.Fatalf("validate leaf: %v", err)
	}

	fmt.Printf("root fingerprint: sha256:%s\n", root.Fingerprint())
	fmt.Printf("leaf fingerprint: sha256:%s\n", leaf.Fingerprint())
}
