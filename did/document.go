package did

import (
	"crypto/ed25519"
	"fmt"
	"strconv"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/mr-tron/base58"
)

const (
	AuthenticationDIDType = "MailioDIDAuth"
	MessagingDIDType      = "DIDCommMessaging"
)

func NewMailioDIDDocument(mk *MailioKey, mailioPublicKey ed25519.PublicKey, AuthServiceEndpoint string, MessageServiceEndpoint string) (*Document, error) {
	did, err := mk.DIDFromKey()
	if err != nil {
		return nil, err
	}

	mailioMk := &MailioKey{
		MasterSignKey: &Key{
			Type:      KeyTypeEd25519,
			PublicKey: mailioPublicKey,
		},
	}
	mailioDid, mErr := mailioMk.DIDFromKey()
	if mErr != nil {
		return nil, mErr
	}

	// A set of parameters that can be used together with a process to independently verify a proof.
	// For example, a cryptographic public key can be used as a verification method with respect to a digital signature;
	// in such usage, it verifies that the signer possessed the associated cryptographic private key.
	verificationMethods := make([]VerificationMethod, 0)

	// add master key in there
	if mk.MasterSignKey != nil {
		rawKey, rkErr := jwk.FromRaw(mk.MasterSignKey.PublicKey)
		if rkErr != nil {
			return nil, rkErr
		}
		pk := &PublicKeyJwk{
			Key: rawKey.(jwk.Key),
		}
		verificationMethod := VerificationMethod{
			Type:         PublicKeyJwkType,
			Controller:   did.String(),
			PublicKeyJwk: pk,
			ID:           did.String() + "#master",
		}
		verificationMethods = append(verificationMethods, verificationMethod)
	}

	// KeyAgreement in DID is used to specify the cryptographic key exhange algorithm between two parties
	keyAgreements := make([]KeyAgreement, 0)
	if mk.MasterAgreementKey != nil {
		agreementMethod := KeyAgreement{
			Type:               KeyTypeX25519KeyAgreement,
			Controller:         did.String(),
			PublicKeyMultibase: base58.Encode(mk.MasterAgreementKey.PublicKey),
			ID:                 did.String(),
		}
		keyAgreements = append(keyAgreements, agreementMethod)
	}

	if len(mk.VerificationKeys) > 0 {
		for i, vk := range mk.VerificationKeys {
			rawKey, rkErr := jwk.FromRaw(vk.PublicKey)
			if rkErr != nil {
				return nil, rkErr
			}

			pk := &PublicKeyJwk{
				Key: rawKey.(jwk.Key),
			}
			verificationMethod := VerificationMethod{
				Type:         PublicKeyJwkType,
				Controller:   did.String(),
				PublicKeyJwk: pk,
				ID:           "#" + strconv.Itoa(i+1),
			}
			verificationMethods = append(verificationMethods, verificationMethod)
		}
	}

	// The authentication verification relationship is used to specify how the DID subject is expected to be authenticated,
	// for purposes such as logging into a website or engaging in any sort of challenge-response protocol.
	authMethods := make([]interface{}, 0)
	authMethod := did.String() + "#master"
	// default auth method uses master key to prove ownership
	authMethods = append(authMethods, authMethod)

	if len(mk.AuthenticationKeys) > 0 {
		for _, vk := range mk.AuthenticationKeys {
			rawKey, rkErr := jwk.FromRaw(vk.PublicKey)
			if rkErr != nil {
				return nil, rkErr
			}

			pk := &PublicKeyJwk{
				Key: rawKey.(jwk.Key),
			}
			authMethod := VerificationMethod{
				Type:         PublicKeyJwkType,
				Controller:   did.String(),
				PublicKeyJwk: pk,
			}
			authMethods = append(authMethods, authMethod)
		}
	}

	doc := &Document{
		Context: []string{
			CtxDIDv1,
			CtxSecEd25519_2020v1,
			CtxSecX25519_2019v1,
		},
		ID:                 did,
		VerificationMethod: verificationMethods,
		Authentication:     authMethods,
		Service: []Service{
			{
				ID:              mailioDid.String() + "#auth",
				Type:            AuthenticationDIDType,
				ServiceEndpoint: fmt.Sprintf("%s/%s", AuthServiceEndpoint, did.Value()),
			},
			{
				ID:              mailioDid.String() + "#didcomm",
				Type:            MessagingDIDType,
				ServiceEndpoint: fmt.Sprintf("%s/%s", MessageServiceEndpoint, did.Value()),
				Accept:          []string{"didcomm/v2", "didcomm/aip2;env=rfc587"},
			},
		},
		KeyAgreement: keyAgreements,
	}
	return doc, nil
}
