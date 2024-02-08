package did

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	MCed25519 = 0xED

	KeyTypeEd25519 = "Ed25519VerificationKey2020"

	PublicKeyJwkType = "JsonWebKey2020"

	KeyTypeX25519KeyAgreement = "X25519KeyAgreementKey2019"

	DIDKeyPrefix = "did:mailio:"
)

var (
	ErrInvalidSignature = fmt.Errorf("invalid signature")

	mcToType = map[uint64]string{
		MCed25519: KeyTypeEd25519,
	}

	typeToMc = map[string]uint64{
		KeyTypeEd25519: MCed25519,
	}
)

type MailioKey struct {
	MasterSignKey      *Key
	MasterAgreementKey *Key
	VerificationKeys   []*Key
	AuthenticationKeys []*Key
}

type Key struct {
	PublicKey ed25519.PublicKey
	Type      string
}

func (k *MailioKey) KeyType() string {
	return k.MasterSignKey.Type
}

func (k *MailioKey) DIDFromKey() (DID, error) {
	if k.MasterSignKey == nil {
		return DID{}, fmt.Errorf("master key required")
	}

	didStr := DIDKeyPrefix + k.MailioAddress()

	id, err := ParseDID(didStr)
	if err != nil {
		// This is probably an invariant violation...
		return DID{}, err
	}

	return id, nil

}

func (k *MailioKey) DID() string {
	return DIDKeyPrefix + k.MailioAddress()
}

func (k *MailioKey) MailioAddress() string {
	hasher := sha256.New()
	pubKey := k.MasterSignKey.PublicKey
	b64Encoded := base64.StdEncoding.EncodeToString(pubKey)
	hasher.Write([]byte(b64Encoded))
	sha256Key := hex.EncodeToString(hasher.Sum(nil))
	return "0x" + sha256Key[64-40:64]
}
