package did

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestNewVerifiableCredential(t *testing.T) {
	serverMk, _ := GenerateMailioPublicKeys()
	targetAppMk, _ := GenerateMailioPublicKeys()
	userMk, _ := GenerateMailioPublicKeys()
	vc := NewVerifiableCredential(serverMk.DID())
	if vc == nil {
		t.Fatal("vc is nil")
	}

	vc.ID = "http://example.edu/credentials/3732"

	credentialSubject := CredentialSubject{
		ID: userMk.DID(),
		AuthorizedApplication: &AuthorizedApplication{
			ID:           targetAppMk.DID(),
			Domains:      []string{"example.com"},
			ApprovalDate: time.Now(),
		},
	}

	vc.CredentialStatus = &CredentialStatus{
		ID:   "https://example.edu/credentials/status/24",
		Type: "CredentialStatusList2017",
	}
	vc.CredentialSubject = credentialSubject

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	vcErr := vc.CreateProof(privateKey)
	if vcErr != nil {
		t.Fatal(vcErr)
	}

	m, _ := json.Marshal(vc)
	fmt.Printf("vc: %s\n", m)

	vcVerify, err := vc.VerifyProof(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !vcVerify {
		t.Fatal("vcVerify is false")
	}
}
