package client

import (
	"crypto"
	"errors"
	"io"

	"github.com/docker/parsec/client/operations/asym_sign"
	"github.com/docker/parsec/client/operations/asym_verify"
	"github.com/docker/parsec/client/operations/key_attributes"
	"github.com/docker/parsec/client/requests"
	"github.com/sirupsen/logrus"

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
	VerifyingKey
	crypto.Signer
}

// DecryptingKey defines an interface for a private key used to decrypt data
type DecryptingKey interface {
	Key
	crypto.Decrypter
}

type key struct {
	KeyID      types.KeyID
	conn       *conn
	attributes types.KeyAttributes
}

// Sign signs a digest using the private key stored in the Parsec backedn
func (key key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	asymSign := &asym_sign.OpAsymmetricSignProto{
		KeyName:     string(key.KeyID),
		KeyLifetime: key_attributes.KeyLifetime(key.attributes.Lifetime),
		Hash:        digest,
	}
	req, err := requests.NewRequest(requests.OpAsymSign, asymSign)
	if err != nil {
		logrus.Errorf("Sign: marshalling error: %v", err)
		return nil, err
	}
	reqBuf, err := req.Pack()
	if err != nil {
		logrus.Errorf("Sign: packing error: %v", err)
		return nil, err
	}

	logrus.Debugf("Signing: %v", reqBuf)
	//TODO output over socket k.conn

	respBuf := reqBuf // FIXME
	asymSignResp := &asym_sign.ResultAsymmetricSignProto{}
	_, err = requests.NewResponse(respBuf, asymSignResp)

	return asymSignResp.Signature, nil
}

// Verify verifies a signature given a digest with the public key
func (key key) Verify(digest []byte, signature []byte) (err error) {
	asymVerify := &asym_verify.OpAsymmetricVerifyProto{
		KeyName:     string(key.KeyID),
		KeyLifetime: key_attributes.KeyLifetime(key.attributes.Lifetime),
		Hash:        digest,
		Signature:   signature,
	}
	req, err := requests.NewRequest(requests.OpAsymVerify, asymVerify)
	if err != nil {
		logrus.Errorf("Verify: marshalling error: %v", err)
		return err
	}
	reqBuf, err := req.Pack()
	if err != nil {
		logrus.Errorf("Verify: packing error: %v", err)
		return err
	}
	logrus.Debugf("Verifying: %v", reqBuf)
	//TODO output over socket

	respBuf := reqBuf // FIXME
	asymVerifyResp := &asym_verify.ResultAsymmetricVerifyProto{}
	resp, err := requests.NewResponse(respBuf, asymVerifyResp)
	if resp.Header.Status != requests.RespSuccess {
		logrus.Errorf("Verify: failed (status code: %v)", resp.Header.Status)
		return errors.New("Verify: failed")
	}

	return nil
}
