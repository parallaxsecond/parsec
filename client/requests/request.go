package requests

import (
	"bytes"
	"encoding/binary"

	"github.com/gogo/protobuf/proto"
)

const requestHeaderSize uint16 = 22

// RequestHeader represents a request header
type RequestHeader struct {
	magicNumber  uint32
	hdrSize      uint16
	versionMajor uint8
	versionMinor uint8
	Provider     uint8
	Session      uint64
	ContentType  uint8
	AcceptType   uint8
	AuthType     uint8
	BodyLen      uint32
	AuthLen      uint16
	OpCode       uint16
}

// RequestBody represents a marshalled request body
type RequestBody struct {
	*bytes.Buffer
}

// RequestAuth represents a request authentication payload
type RequestAuth struct {
	*bytes.Buffer
}

// Request represents a Parsec request
type Request struct {
	Header RequestHeader
	Body   RequestBody
	Auth   RequestAuth
}

func (r *RequestHeader) pack(buf *bytes.Buffer) error {
	r.magicNumber = magicNumber
	r.hdrSize = requestHeaderSize
	err := binary.Write(buf, binary.LittleEndian, r)
	return err
}

// NewRequestAuth creates a new request authentication payload
func NewRequestAuth() (*RequestAuth, error) {
	r := &RequestAuth{&bytes.Buffer{}}
	return r, nil
}

// NewRequest creates a new request
func NewRequest(op uint16, bdy proto.Message) (*Request, error) {
	bodyBuf, err := proto.Marshal(bdy)
	if err != nil {
		return nil, err
	}
	// FIXME
	auth, err := NewRequestAuth()
	if err != nil {
		return nil, err
	}
	r := &Request{
		Header: RequestHeader{
			OpCode:  op,
			BodyLen: uint32(len(bodyBuf)),
			AuthLen: uint16(auth.Len()),
		},
		Body: RequestBody{
			bytes.NewBuffer(bodyBuf),
		},
		Auth: *auth,
	}
	return r, nil
}

// Pack encodes a request to the wire format
func (r *Request) Pack() (*bytes.Buffer, error) {
	b := bytes.NewBuffer([]byte{})
	r.Header.pack(b)
	b.Write(r.Body.Bytes())
	b.Write(r.Auth.Bytes())
	return b, nil
}
