package api

import (
	"crypto"

	"github.com/pasl/client/api/types"
)

// CommonAPIClient is the common methods between stable and experimental versions of APIClient.
type CommonAPIClient interface {
	KeyManagerClient
	SystemClient
	Close() error
}

// KeyManagerClient defines API client methods for key management
type KeyManagerClient interface {
	KeyCreate(keyid string, params types.KeyParams) (Key, error)
	KeyImport(keyid string, key Key) (Key, error)
	KeyExport(keyid string) (Key, error)
	KeyDelete(keyid) error
}

// SystemClient defines API client methods for the PASL system
type SystemClient interface {
	Info() (types.Info, error)
}

// Key defines a generic key interface
type Key interface{}

// VerifyingKey refers to a public key for verifying signatures
type VerifyingKey interface {
	Key
	crypto.PublicKey
	Verify(digest []byte, signature []byte) error
}

// SigningKey refers to a private key for signing hashes
type SigningKey interface {
	Key
	VerifyingKey
	crypto.Signer
	Sign(digest []byte) (signature []byte, err error)
}
