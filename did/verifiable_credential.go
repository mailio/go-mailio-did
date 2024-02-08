package did

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func NewVerifiableCredential(mailioDID string) *VerifiableCredential {
	return &VerifiableCredential{
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		Type:         []string{"VerifiableCredential", "MailioAppCredential"},
		Issuer:       mailioDID,
		IssuanceDate: time.Now(),
	}
}

// CreateProof creates a proof for Verifiable Credential using private key from a signer
func (vc *VerifiableCredential) CreateProof(privateKey ed25519.PrivateKey) error {
	cbor, err := cbor.Marshal(vc)
	if err != nil {
		return err
	}

	svo := jws.WithKey(jwa.EdDSA, privateKey)
	signature, err := jws.Sign(cbor, svo)
	if err != nil {
		return err
	}

	vc.Proof = &Proof{
		Type:               KeyTypeEd25519,
		Created:            time.Now(),
		ProofPurpose:       "assertionMethod",
		VerificationMethod: vc.Issuer,
		Jws:                string(signature),
	}
	return nil
}

// Verify if the proof of Verifialbe Credential is valid using public key from a signer
func (vc *VerifiableCredential) VerifyProof(publicKey ed25519.PublicKey) (bool, error) {
	if vc.Proof == nil {
		return false, errors.New("Proof is nil")
	}
	if vc.Proof.Jws == "" {
		return false, errors.New("Jws is empty")
	}

	message := vc.Proof.Jws
	svo := jws.WithKey(jwa.EdDSA, publicKey)

	contentPayload, err := jws.Verify([]byte(message), svo)
	if err != nil {
		return false, err
	}
	var vcVerify VerifiableCredential
	umsErr := cbor.Unmarshal(contentPayload, &vcVerify)
	if umsErr != nil {
		return false, umsErr
	}
	if vcVerify.Issuer != vc.Issuer {
		return false, errors.New("Issuer is not match")
	}

	return true, nil
}
