package did

import "testing"

func TestParseDID(t *testing.T) {
	did, err := ParseDID("did:mailio:1234")
	if err != nil {
		t.Fatal(err)
	}
	if did.Value() != "1234" {
		t.Fatal("invalid value")
	}
	if did.Protocol() != "mailio" {
		t.Fatal("invalid protocol")
	}
	if did.String() != "did:mailio:1234" {
		t.Fatal("invalid string")
	}
}

func TestParseWebDID(t *testing.T) {
	did, err := ParseDID("did:web:mail.io#0xAlice")
	if err != nil {
		t.Fatal(err)
	}
	if did.Value() != "mail.io" {
		t.Fatal("invalid value")
	}
	if did.Protocol() != "web" {
		t.Fatal("invalid protocol")
	}
	if did.String() != "did:web:mail.io#0xAlice" {
		t.Fatal("invalid string")
	}
	if did.Fragment() != "0xAlice" {
		t.Fatal("invalid fragment")
	}
}
