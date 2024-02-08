package did

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
)

// test keys
// signature keys supported: ed25519
// auth encryption keys supported: x25519
func GenerateMailioPublicKeys() (*MailioKey, error) {
	ret := &MailioKey{
		MasterSignKey: &Key{
			Type: KeyTypeEd25519,
		},
		MasterAgreementKey: &Key{
			Type: KeyTypeX25519KeyAgreement,
		},
	}

	// master signing key
	rng := rand.Reader
	_, edpriv, edErr := ed25519.GenerateKey(rng)
	if edErr != nil {
		return nil, fmt.Errorf("ed25519 key generation failed: %w", edErr)
	}
	ret.MasterSignKey.PublicKey = edpriv.Public().(ed25519.PublicKey)

	// master agreement key
	pub, _, pkErr := CreateX25519ECDSAKeys()
	if pkErr != nil {
		return nil, pkErr
	}
	ret.MasterAgreementKey.PublicKey = pub

	return ret, nil
}

// only for testing purposes, otherwise this is created by
func CreateX25519ECDSAKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, err
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	pk := ed25519.PublicKey(publicKey)
	pr := ed25519.PrivateKey(privateKey)
	// pk := crypto.PublicKey(publicKey)
	// pr := crypto.PrivateKey(privateKey)

	return pk, pr, nil
}

func TestDIDFromKey(t *testing.T) {
	mk, err := GenerateMailioPublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	did, err := mk.DIDFromKey()
	if err != nil {
		t.Fatal(err)
	}
	expected := mk.MailioAddress()
	assert.Equal(t, expected, did.Value())
}

func TestGetValidationMethodPublicKeys(t *testing.T) {
	mk, err := GenerateMailioPublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	mkMailio, _ := GenerateMailioPublicKeys()
	doc, err := NewMailioDIDDocument(mk, mkMailio.MasterSignKey.PublicKey, AuthServiceEndpoint, MessageServiceEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	userDID, _ := mk.DIDFromKey()
	masterVerificationPublicKey, err := doc.GetVerificationPublicKey(userDID.String() + "#master")
	if err != nil {
		t.Fatal(err)
	}
	keyOne := ed25519.PublicKey((*masterVerificationPublicKey).([]byte))
	if !bytes.Equal(keyOne, mk.MasterSignKey.PublicKey) {
		t.Fatal("master verification key is not equal")
	}
}

func TestGetKeyAgreementPublicKey(t *testing.T) {
	mk, err := GenerateMailioPublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	mkMailio, _ := GenerateMailioPublicKeys()
	doc, err := NewMailioDIDDocument(mk, mkMailio.MasterSignKey.PublicKey, AuthServiceEndpoint, MessageServiceEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	for _, keyAgreement := range doc.KeyAgreement {
		kaPublicKey, kaErr := keyAgreement.GetPublicKey()
		if kaErr != nil {
			t.Fatal(kaErr)
		}
		keyOne := (*kaPublicKey).([]byte)
		keyTwo := mk.MasterAgreementKey.PublicKey
		if !bytes.Equal(keyOne, keyTwo) {
			t.Fatal("key agreement key is not equal")
		}
	}
}

func TestAuthenticationPublicKey(t *testing.T) {
	mk, _ := GenerateMailioPublicKeys()
	mkMailio, _ := GenerateMailioPublicKeys()
	doc, _ := NewMailioDIDDocument(mk, mkMailio.MasterSignKey.PublicKey, AuthServiceEndpoint, MessageServiceEndpoint)

	var authPublicKey *crypto.PublicKey
	for _, auth := range doc.Authentication {
		switch v := auth.(type) {
		case string:
			apk, _ := doc.GetVerificationPublicKey(v)
			authPublicKey = apk
			break
		case map[string]interface{}:
			t.Fatal("shouldn't be here")
			break
		default:
			t.Fatal("shouldn't be here")
		}
	}
	keyOne := (*authPublicKey).([]byte)
	keyTwo := mk.MasterSignKey.PublicKey
	if !bytes.Equal(keyOne, keyTwo) {
		t.Fatal("authentication key is not equal")
	}
}

func TestCryptoPublicKeyType(t *testing.T) {
	mk, _ := GenerateMailioPublicKeys()
	signingKeyBytes, _ := base64.StdEncoding.DecodeString("lTi99FcVgGAuoHblyw0pffGs3GwZudOT3XDjZ9d7cKc=")
	signingKey := ed25519.PublicKey(signingKeyBytes)

	mk.MasterSignKey.PublicKey = signingKey
	mkMailio, _ := GenerateMailioPublicKeys()
	doc, _ := NewMailioDIDDocument(mk, mkMailio.MasterSignKey.PublicKey, AuthServiceEndpoint, MessageServiceEndpoint)
	fmt.Printf("%+v\n", doc)
}
