package client

import (
  "io"
  "crypto"
  "github.com/docker/parsec/types"
)

// Key defines an interface for any cryptographic key
type Key interface {
}

// VerifyingKey defines an interface for a public key used to verify digital signatures
type VerifyingKey interface {
  Key
  crypto.PublicKey
  Verify(digest []byte, signature []byte) error
}

// SigningKey defines an interface for a private key used to generate digital signatures
type SigningKey interface {
  Key
  crypto.Signer
}

// DecryptingKey defines an interface for a private key used to decrypt data
type DecryptingKey interface {
  Key
  crypto.Decrypter
}

type key struct {
  conn *conn
  attributes types.KeyAttributes
}

func (key key) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return nil, nil
}
