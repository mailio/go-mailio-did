# Mailio Decentralized Indetifiers (DID) 

_The implementation is loosely based on this repository: [https://github.com/whyrusleeping/go-did](https://github.com/whyrusleeping/go-did)_

**Run tests**
```
make test
```

Example Mailio DID document:

```json
{
	"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1", "https://w3id.org/security/suites/x25519-2019/v1"],
	"id": "did:mailio:0xedccad2a5fc72c7924eed3a93ca631cd6b1f02de",
	"authentication": ["did:mailio:0xedccad2a5fc72c7924eed3a93ca631cd6b1f02de#master"],
	"verificationMethod": [{
		"id": "did:mailio:0xedccad2a5fc72c7924eed3a93ca631cd6b1f02de#master",
		"type": "JsonWebKey2020",
		"controller": "did:mailio:0xedccad2a5fc72c7924eed3a93ca631cd6b1f02de",
		"publicKeyJwk": {
			"crv": "Ed25519",
			"kty": "OKP",
			"x": "RlpTGFFWyaPo_-eM8vDaZ_LPFgoVYnBeeo5c4d_6pQQ"
		}
	}],
	"keyAgreement": [{
		"id": "did:mailio:0xedccad2a5fc72c7924eed3a93ca631cd6b1f02de",
		"type": "X25519KeyAgreementKey2019",
		"controller": "did:mailio:0xedccad2a5fc72c7924eed3a93ca631cd6b1f02de",
		"publicKeyMultibase": "2NFu1v4xS8QxgfkoaqarGv6rV6mEqpXht1SxQqR2QXgg"
	}],
	"service": [{
		"id": "did:mailio:0x7baa1e7c6af409a1b8125ef15553192c4682c17e#auth",
		"type": "MailioDIDAuth",
		"serviceEndpoint": "https://api.mail.io/api/v1/didauth/did:mailio:0xedccad2a5fc72c7924eed3a93ca631cd6b1f02de"
	}, {
		"id": "did:mailio:0x7baa1e7c6af409a1b8125ef15553192c4682c17e#didcomm",
		"type": "DIDCommMessaging",
		"serviceEndpoint": "https://api.mail.io/api/v2/didmessage/did:mailio:0xedccad2a5fc72c7924eed3a93ca631cd6b1f02de",
		"accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
	}]
}
```

## Mailio DID

Mailio DID is composed based on [Igor Rendulic, "MIR-11: Mailio Decentralized Identifiers (DIDs) [DRAFT]," Mailio Improvement Proposals, no. 11, September 2022. [Online serial].](https://mirs.mail.io/MIRS/mir-11)

## Mailio Verification Methods

A set of parameters that can be used together with a process to independently verify a proof.

For example, a cryptographic public key can be used as a verification method with respect to a digital signature; in such usage, it verifies that the signer possessed the associated cryptographic private key.

## Mailio DID Authentication

The authentication is used to specify how the Mailio DID subject is expected to be authenticated, for purposes such as logging into a website / engaging in challenge-response protocol.

## Mailio KeyAgreement

The keyAgreement in Mailio is used to specify how an entity can generate encryption material in order to transmit confidential information intended for the Mailio DID, such as for the purposes of establishing a secure communication channel with the recipient. 

[Igor Rendulic, "MIR-12: Mailio Communication Protocol [DRAFT]," Mailio Improvement Proposals, no. 12, September 2022. [Online serial]. Available: https://mirs.mail.io/MIRS/mir-12.](https://mirs.mail.io/MIRS/mir-12.)

## Mailio Service

Services are used to express ways of communicating with the Mailio DID subjects. 

Mailio supports two types of services: 
- MailioDIDAuth specifying an authentication endpoint
- DIDCommMessaging specifying an endpoint for messaging with a DID subject and supported DIDComm version

[Igor Rendulic, "MIR-12: Mailio Communication Protocol [DRAFT]," Mailio Improvement Proposals, no. 12, September 2022. [Online serial]. Available: https://mirs.mail.io/MIRS/mir-12.](https://mirs.mail.io/MIRS/mir-12.)


