package apcb

//
// See: AgesaPkg/Addendum/Apcb/Inc/CommonV3/ApcbV3Arch.h for more details
//

type headerSignature uint32

const (
	headerV2Signature       headerSignature = 0x42435041
	headerV3Signature       headerSignature = 0x32424345
	headerV3EndingSignature headerSignature = 0x41424342
)

type headerV2 struct {
	// ASCII "APCB", 'A' is LSB
	Signature headerSignature
	// Size of header
	SizeOfHeader uint16
	// Version, BCD. Version 1.2 is 0x12
	Version uint16
	// SizeOfAPCB is size of APCB
	SizeOfAPCB uint32
	// UniqueAPCBInstance to ensure compatibility for given flashed BIOS life cycle
	UniqueAPCBInstance uint32
	// CheckSumByte is APCB Checksum Byte
	CheckSumByte uint8
	// Reserved1 is reserved, should be zeros
	Reserved1 [3]uint8
	// Reserved2 is reserved, should be zeros
	Reserved2 [3]uint32
}

type headerV3 struct {
	V2Header headerV2

	// Signature2 is "ECB2", 'E' is LSB
	Signature2 headerSignature
	// ReservedFixed1 fixed with 0. To be compatible with APCB_GROUP_HEADER_COMP.GroupId
	ReservedFixed1 uint16
	// Reserved, fixed with 0x10. To be compatible with APCB_GROUP_HEADER_COMP.SizeOfHeader
	ReservedFixed2 uint16

	// StructVersion integer. 0x12 is Version 18.
	StructVersion uint16 // Version, Hex. integer. 0x12 is Version 18.
	// DataVersion 0x100 is Version 256.
	DataVersion uint16
	// SizeOfExtendedHeader - size of extended header (size of APCB_v3_HEADER minus APCB_v2_HEADER). To be compatible with APCB_GROUP_HEADER_COMP.SizeOfGroup
	SizeOfExtendedHeader uint32

	// ReservedFixed3 fixed with 0. To be compatible with APCB_TYPE_HEADER.GroupId
	ReservedFixed3 uint16
	// ReservedFixed4 fixed with 0xFFFF. To be compatible with APCB_TYPE_HEADER.TypeId
	ReservedFixed4 uint16
	//  ReservedFixed5 fixed with 64d, 0x40, value to include extended header. To be compatible with APCB_TYPE_HEADER.SizeOfType
	ReservedFixed5 uint16
	// ReservedFixed6 fixed with 0x0000. To be compatible with APCB_TYPE_HEADER.InstanceId
	ReservedFixed6 uint16
	// Reserved3 should be zeros
	Reserved3 [2]uint32

	// DataOffset defines data starting offset, defined per APCB version. Fixed at size of APCB_V3_HEADER (88d, 0x58)
	DataOffset uint16

	// HeaderCheckSum is headerV3 Checksum Byte, needs to be filled
	HeaderCheckSum uint8
	// Reserved4 should be zeros
	Reserved4 uint8
	// Reserved5 should be zeros
	Reserved5 [3]uint32

	// APCB integrity signature, 0x20, 32 bytes
	IntegritySignature [32]uint8
	// Reserved6 should be zeros
	Reserved6 [3]uint32
	// SignatureEnding should be ASCII "BCPA", 'B' is LSB, Mark ending of header
	SignatureEnding headerSignature
}

type groupHeader struct {
	// ASCII Signature
	Signature    headerSignature
	GroupID      groupID
	SizeOfHeader uint16
	// Version, BCD. Version 1.2 is 0x12
	Version     uint16
	Reserved    uint16
	SizeOfGroup uint32
}

type contextType uint8

const (
	structureContextType contextType = 0
	parameterContextType contextType = 1
	tokenV3ContextType   contextType = 2
)

type contextFormat uint8

const (
	nativeRawContextFormat          contextFormat = 0
	sortAscByUnitSizeContextFormat  contextFormat = 1
	sortDescByUnitSizeContextFormat contextFormat = 2
)

type tokenType uint16

const (
	booleanTokenType   tokenType = 0
	oneByteTokenType   tokenType = 1
	twoBytesTokenType  tokenType = 2
	fourBytesTokenType tokenType = 4
)

type groupID uint16

const (
	tokensGroupID groupID = 0x3000
)

type typeHeaderV3 struct {
	GroupID groupID
	TypeID  tokenType
	// SizeOfType defines size of type, in bytes
	SizeOfType uint16
	InstanceID uint16

	ContextType   contextType
	ContextFormat contextFormat
	// UnitSize determines size in byte. Applicable when ContextType = 2, value should be 8.
	UnitSize     uint8
	PriorityMask PriorityMask
	// KeySize defines sorting key size. Should be smaller than or equal to UnitSize. Applicable when ContextFormat = 1. (or != 0)
	KeySize uint8
	// KeyPos defines Sorting key position of the unit specified of UnitSize.
	KeyPos uint8
	// Board specific APCB instance mask
	BoardMask uint16
}

type tokenPair struct {
	ID    TokenID
	Value uint32
}
