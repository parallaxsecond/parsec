package requests

import (
	"bytes"
	"encoding/binary"

	"github.com/gogo/protobuf/proto"
)

const responseHeaderSize uint16 = 20

// Response codes
const (
	RespSuccess                      uint16 = 0
	RespWrongProviderID              uint16 = 1
	RespContentTypeNotSupported      uint16 = 2
	RespAcceptTypeNotSupported       uint16 = 3
	RespVersionTooBig                uint16 = 4
	RespProviderNotRegistered        uint16 = 5
	RespProviderDoesNotExist         uint16 = 6
	RespDeserializingBodyFailed      uint16 = 7
	RespSerializingBodyFailed        uint16 = 8
	RespOpcodeDoesNotExist           uint16 = 9
	RespResponseTooLarge             uint16 = 10
	RespUnsupportedOperation         uint16 = 11
	RespAuthenticationError          uint16 = 12
	RespAuthenticatorDoesNotExist    uint16 = 13
	RespAuthenticatorNotRegistered   uint16 = 14
	RespKeyDoesNotExist              uint16 = 15
	RespKeyAlreadyExists             uint16 = 16
	RespPsaErrorGenericError         uint16 = 1132
	RespPsaErrorNotPermitted         uint16 = 1133
	RespPsaErrorNotSupported         uint16 = 1134
	RespPsaErrorInvalidArgument      uint16 = 1135
	RespPsaErrorInvalidHandle        uint16 = 1136
	RespPsaErrorBadState             uint16 = 1137
	RespPsaErrorBufferTooSmall       uint16 = 1138
	RespPsaErrorAlreadyExists        uint16 = 1139
	RespPsaErrorDoesNotExist         uint16 = 1140
	RespPsaErrorInsufficientMemory   uint16 = 1141
	RespPsaErrorInsufficientStorage  uint16 = 1142
	RespPsaErrorInssuficientData     uint16 = 1143
	RespPsaErrorCommunicationFailure uint16 = 1145
	RespPsaErrorStorageFailure       uint16 = 1146
	RespPsaErrorHardwareFailure      uint16 = 1147
	RespPsaErrorInsufficientEntropy  uint16 = 1148
	RespPsaErrorInvalidSignature     uint16 = 1149
	RespPsaErrorInvalidPadding       uint16 = 1150
	RespPsaErrorTamperingDetected    uint16 = 1151
)

// ResponseHeader represents a respsonse header
type ResponseHeader struct {
	magicNumber  uint32
	hdrSize      uint16
	versionMajor uint8
	versionMinor uint8
	Provider     uint8
	Session      uint64
	ContentType  uint8
	AuthType     uint8
	BodyLen      uint32
	OpCode       uint16
	Status       uint16
}

// ResponseBody represents a response body
type ResponseBody struct {
	body *bytes.Buffer
}

// Response represents a Parsec response
type Response struct {
	Header ResponseHeader
	Body   ResponseBody
}

func (r *ResponseHeader) parse(buf *bytes.Buffer) error {
	err := binary.Read(buf, binary.LittleEndian, r)
	return err
}

// NewResponse returns a response if it successfuly unmarshals the given byte buffer
func NewResponse(buf *bytes.Buffer, pb proto.Message) (*Response, error) {
	r := &Response{}
	hdrBuf := make([]byte, responseHeaderSize)
	_, err := buf.Read(hdrBuf)

	r.Header.parse(bytes.NewBuffer(hdrBuf))
	//TODO sanity check r.Header values

	bodyBuf := make([]byte, r.Header.BodyLen)
	r.Body.body = bytes.NewBuffer(bodyBuf)
	err = proto.Unmarshal(r.Body.body.Bytes(), pb)

	return r, err
}
