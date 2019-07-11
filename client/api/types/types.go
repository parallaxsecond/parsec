package types

import (
	"crypto"
	"crypto/elliptic"
	"math/big"
)

// KeyType is a bitmask of types
type KeyType uint32

// SignKeyParams detail the parameters for a signing key
type SignKeyParams struct {
	ECCParams struct {
		CurveID elliptic.Curve
	}
	RSAParams struct {
		KeyBits uint16
		Modulus big.Int
	}
	HashAlg crypto.Hash
}

// EncryptKeyParams detail the parameters for an encryption key
type EncryptKeyParams struct{}

// Info lists general information of the service
type Info struct{}

// KeyParams detail the parameters of a key
type KeyParams struct {
	KeyType       KeyType
	SignParams    SignKeyParams
	EncryptParams EncryptKeyParams
}
