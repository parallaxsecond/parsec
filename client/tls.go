package client

import (
  "errors"
  "crypto/tls"
  "encoding/pem"
)

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
