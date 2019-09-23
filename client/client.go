package client

import (
	"github.com/docker/parsec/types"
)

// Client is a Parsec client representing a connection and set of API implementations
type Client struct {
	*conn
	SystemClient
	KeyManagerClient
}

// KeyManagerClient is an interface to the key management facilities of Parsec
type KeyManagerClient interface {
	KeyGet(keyid types.KeyID) (Key, error)
	KeyImport(k Key) error
	KeyDelete(keyid types.KeyID) error
	KeyList() ([]Key, error)
}

// SystemClient is an interface to the system calls of Parsec
type SystemClient interface {
	Version() string
	Info() (types.Info, error)
}

// InitClient initializes a Parsec client
func InitClient() (*Client, error) {
	return nil, nil
}

// KeyGet obtains a key from Parsec by KeyID
func (c Client) KeyGet(keyid types.KeyID) (Key, error) {
	return &key{}, nil
}
