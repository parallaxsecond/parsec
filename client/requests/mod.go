package requests

const magicNumber uint32 = 0x5EC0A710

// Operation Codes
const (
	OpPing            uint16 = 0
	OpCreateKey       uint16 = 1
	OpDestroyKey      uint16 = 2
	OpAsymSign        uint16 = 3
	OpAsymVerify      uint16 = 4
	OpImportKey       uint16 = 5
	OpExportPublicKey uint16 = 6
)
