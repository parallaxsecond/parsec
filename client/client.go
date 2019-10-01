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
	client := &Client{
		conn: &conn{},
	}

	err := client.conn.open()
	if err != nil {
		return nil, err
	}
	err = client.conn.close()
	if err != nil {
		return nil, err
	}

	//TODO version or other init
	return client, nil
}

// KeyGet obtains a key from Parsec by KeyID
func (c Client) KeyGet(keyid types.KeyID, attributes types.KeyAttributes) (Key, error) {
	k := &key{
		KeyID:      keyid,
		conn:       c.conn,
		attributes: attributes,
	}
	//TODO some method of testing key presence (ListKeys?)
	return &k, nil
}
