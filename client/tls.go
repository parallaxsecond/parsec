package client

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"

	"github.com/docker/parsec/types"
)

type keyCfg struct {
	KeyID       string `json:"parsec_key_id"`
	KeyLifetime int32  `json:"parsec_key_lifetime`
}

func parseConfigFile(filepath string) (*keyCfg, error) {
	keyData, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	cfg := &keyCfg{}
	err = json.Unmarshal(keyData, cfg)
	return cfg, err
}

// IsParsecKeyFile returns if a keyfile refers to a Parsec-backed key
func IsParsecKeyFile(filepath string) bool {
	_, err := parseConfigFile(filepath)
	return err == nil
}

// GetKeyID loads a key ID from file
func GetKeyID(filepath string) (types.KeyID, error) {
	cfg, err := parseConfigFile(filepath)
	if err != nil {
		return "", err
	}
	return types.KeyID(cfg.KeyID), nil
}

// GetKeyAttributes loads key attributes from a file
func GetKeyAttributes(filepath string) (*types.KeyAttributes, error) {
	cfg, err := parseConfigFile(filepath)
	if err != nil {
		return nil, err
	}
	a := &types.KeyAttributes{
		Lifetime: types.KeyLifetime(cfg.KeyLifetime),
	}
	return a, nil
}

// X509KeyPair returns a TLS certificate based on a PEM-encoded certificate and a parsec defined private key
func X509KeyPair(certPEMBlock []byte, k Key) (*tls.Certificate, error) {
	cert := &tls.Certificate{}
	cert.PrivateKey = k
	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil {
		return nil, errors.New("Failed to read certificate")
	}
	if certDERBlock.Type == "CERTIFICATE" {
		cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
	}
	return cert, nil
}
