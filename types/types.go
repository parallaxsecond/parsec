package types

import (
	"github.com/docker/parsec/client/operations/key_attributes"
)

// Info defines all information related to Parsec server
type Info struct {
}

// KeyLifetime refers to the lifetime of a key (volatile or persistent)
type KeyLifetime key_attributes.KeyLifetime

// KeyAttributes defines all attributes that define a Key implementation
type KeyAttributes struct {
	Lifetime KeyLifetime
}

// KeyID represents a key identifier
type KeyID string
