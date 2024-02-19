package did

import (
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/mr-tron/base58"
)

const (
	CtxDIDv1             = "https://www.w3.org/ns/did/v1"
	CtxSecEd25519_2020v1 = "https://w3id.org/security/suites/ed25519-2020/v1"
	CtxSecX25519_2019v1  = "https://w3id.org/security/suites/x25519-2019/v1"
	CtxDIDCommMsg_v2     = "https://didcomm.org/messaging/contexts/v2"
)

type DID struct {
	raw      string
	proto    string
	value    string
	fragment string
}

func (d *DID) String() string {
	return d.raw
}

func (d *DID) Value() string {
	return d.value
}

func (d *DID) Fragment() string {
	return d.fragment
}

func (d DID) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.raw)
}

func (d *DID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	o, err := ParseDID(s)
	if err != nil {
		return err
	}

	*d = o
	return nil
}

func (d *DID) Protocol() string {
	return d.proto
}

func ParseDID(s string) (DID, error) {
	// Fragment only DID
	if strings.HasPrefix(s, "#") {
		return DID{
			raw:      s,
			fragment: s,
		}, nil
	}

	dfrag := strings.SplitN(s, "#", 2)

	segm := strings.SplitN(dfrag[0], ":", 3)
	if len(segm) != 3 {
		return DID{}, fmt.Errorf("invalid did: must contain three parts: %v", segm)
	}

	if segm[0] != "did" {
		return DID{}, fmt.Errorf("invalid did: first segment must be 'did'")
	}

	var frag string
	if len(dfrag) == 2 {
		frag = "#" + dfrag[1]
		frag = strings.Replace(frag, "#", "", 1)
	}

	return DID{
		raw:      s,
		proto:    segm[1],
		value:    segm[2],
		fragment: frag,
	}, nil
}

// Each DID document can express cryptographic material, verification methods, or services,
// which provide a set of mechanisms enabling a DID controller to prove control of the DID.
// Services enable trusted interactions associated with the DID subject.
type Document struct {
	Context []string `json:"@context"`

	ID DID `json:"id"`

	AlsoKnownAs []string `json:"alsoKnownAs,omitempty"`

	Authentication []interface{} `json:"authentication,omitempty"`

	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`

	KeyAgreement []KeyAgreement `json:"keyAgreement,omitempty"`

	Service []Service `json:"service,omitempty"`
}

// Means of communicating or interacting with the DID subject or associated entities via one or more service endpoints.
// Examples include discovery services, agent services, social networking services, file storage services,
// and verifiable credential repository services.
type Service struct {
	ID              string   `json:"id"`
	Type            string   `json:"type"`
	ServiceEndpoint string   `json:"serviceEndpoint"`
	Accept          []string `json:"accept,omitempty"`
	RoutingKeys     []string `json:"routingKeys,omitempty"`
}

// A set of parameters that can be used together with a process to independently verify a proof.
// For example, a cryptographic public key can be used as a verification method with respect to a
// digital signature; in such usage, it verifies that the signer possessed the associated cryptographic private key.
type VerificationMethod struct {
	ID           string        `json:"id,omitempty"`
	Type         string        `json:"type,omitempty"`
	Controller   string        `json:"controller,omitempty"`
	PublicKeyJwk *PublicKeyJwk `json:"publicKeyJwk,omitempty"`
}

// A set of parameters that can be used together with a process to independently derive a shared key or secret
// that can be used for secure communication.
type KeyAgreement struct {
	ID                 string        `json:"id,omitempty"`
	Type               string        `json:"type,omitempty"` // usually X25519KeyAgreementKey2019
	Controller         string        `json:"controller,omitempty"`
	PublicKeyMultibase string        `json:"publicKeyMultibase,omitempty"`
	PublicKeyJwk       *PublicKeyJwk `json:"publicKeyJwk,omitempty"`
}

// get public key from verification method
func (vm VerificationMethod) GetPublicKey() (*crypto.PublicKey, error) {
	if vm.PublicKeyJwk != nil {
		// ed25519 supported key (other yet unsupported)
		jwkKey := vm.PublicKeyJwk.Key
		if jwkKey == nil {
			return nil, fmt.Errorf("no key found in jwk")
		}
		keyType := jwkKey.KeyType()
		switch keyType {
		case jwa.OKP:

			k, err := vm.PublicKeyJwk.GetRawKey()
			if err != nil {
				return nil, err
			}
			ek, ok := k.(ed25519.PublicKey)
			if !ok {
				return nil, fmt.Errorf("only ed25519 keys are currently supported")
			}
			pkRaw := []byte(ek)
			publicKey := crypto.PublicKey(pkRaw)
			return &publicKey, nil
		default:
			return nil, fmt.Errorf("unsupported key type: %s", keyType)
		}
	}

	return nil, fmt.Errorf("no public key specified in verificationMethod")
}

type PublicKeyJwk struct {
	Key jwk.Key
}

func (pkj *PublicKeyJwk) UnmarshalJSON(b []byte) error {
	parsed, err := jwk.Parse(b)
	if err != nil {
		return err
	}

	if parsed.Len() != 1 {
		return fmt.Errorf("expected a single key in the jwk field")
	}

	k, ok := parsed.Key(0)
	if !ok {
		return fmt.Errorf("should be unpossible")
	}

	pkj.Key = k

	return nil
}

func (pkj *PublicKeyJwk) MarshalJSON() ([]byte, error) {
	return json.Marshal(pkj.Key)
}

func (pk *PublicKeyJwk) GetRawKey() (interface{}, error) {
	var rawkey interface{}
	if err := pk.Key.Raw(&rawkey); err != nil {
		return nil, err
	}

	return rawkey, nil
}

// get public key by finding a correct verification method and returning the public key
func (d *Document) GetVerificationPublicKey(id string) (*crypto.PublicKey, error) {
	for _, vm := range d.VerificationMethod {
		if id == vm.ID || id == "" {
			return vm.GetPublicKey()
		}
	}

	return nil, fmt.Errorf("no key found by that ID")
}

// GetPublicKey for an KeyAgreement
func (ka *KeyAgreement) GetPublicKey() (*crypto.PublicKey, error) {
	if ka.PublicKeyMultibase == "" {
		return nil, fmt.Errorf("no public key specified in keyAgreement")
	}
	decoded, err := base58.Decode(ka.PublicKeyMultibase)
	if err != nil {
		return nil, err
	}
	publicKey := crypto.PublicKey(decoded)
	return &publicKey, nil
}

// VerifiableCredential is a JSON-LD document that cryptographically proves that the subject
// identified by the DID has been verified against a given credential schema.
// The Verifiable Credential data model is defined in the W3C Verifiable Credentials Data Model 1.0 specification.
type VerifiableCredential struct {
	Context           []string          `json:"@context"`
	ID                string            `json:"id,omitempty"`
	Type              []string          `json:"type"`
	Issuer            string            `json:"issuer"`
	IssuanceDate      time.Time         `json:"issuanceDate"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
	Proof             *Proof            `json:"proof,omitempty"`
	CredentialStatus  *CredentialStatus `json:"credentialStatus,omitempty"`
}

type Proof struct {
	Type               string    `json:"type"`
	Created            time.Time `json:"created"`
	ProofPurpose       string    `json:"proofPurpose"`
	VerificationMethod string    `json:"verificationMethod"`
	Challenge          string    `json:"challenge,omitempty"` // prevent replay attacks
	Domain             string    `json:"domain,omitempty"`    // prevent replay attacks
	Jws                string    `json:"jws"`
}

type CredentialSubject struct {
	ID                    string                 `json:"id"`
	Origin                string                 `json:"origin,omitempty"`
	AuthorizedApplication *AuthorizedApplication `json:"authorizedApplication,omitempty"`
}

type CredentialStatus struct {
	ID   string `json:"id"`   // https://example.edu/status/24"
	Type string `json:"type"` // CredentialStatusList2017
}

// VerifiablePresentation is a JSON-LD document that cryptographically proves that the holder of the DID
// has been verified against a given credential schema. (response to VC request)
type VerifiablePresentation struct {
	Context              []string               `json:"@context"`
	ID                   string                 `json:"id"`
	Type                 string                 `json:"type"`
	Holder               string                 `json:"holder"`
	VerifiableCredential []VerifiableCredential `json:"verifiableCredential"`
	Proof                Proof                  `json:"proof"`
}

type AuthorizedApplication struct {
	ID              string    `json:"id"`      // target application did: did:example:123456789abcdefghi
	Domains         []string  `json:"domains"` // domains of the auth application: [example.com]
	ApprovalDate    time.Time `json:"approvalDate"`
	UserPermissions []string  `json:"userPermissions,omitempty"` // optional list of permissions specific to a target application
}
