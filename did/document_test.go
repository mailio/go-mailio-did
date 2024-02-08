package did

import (
	"encoding/json"
	"fmt"
	"testing"
)

const (
	AuthServiceEndpoint    = "https://auth.mailio.com"
	MessageServiceEndpoint = "https://msg.mailio.com"
)

func TestNewDocument(t *testing.T) {
	mk, err := GenerateMailioPublicKeys()
	serverMk, err := GenerateMailioPublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, ppErr := CreateX25519ECDSAKeys()
	if ppErr != nil {
		t.Fatal(ppErr)
	}
	mk.MasterAgreementKey = &Key{
		PublicKey: pub,
		Type:      KeyTypeX25519KeyAgreement,
	}
	doc, err := NewMailioDIDDocument(mk, serverMk.MasterSignKey.PublicKey, AuthServiceEndpoint, MessageServiceEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	if doc == nil {
		t.Fatal("document is nil")
	}
	mshld, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("document: %s\n", mshld)
}
