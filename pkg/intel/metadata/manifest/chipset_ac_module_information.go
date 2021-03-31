//go:generate manifestcodegen

package manifest

var chipsetACModuleInformationSignature = []byte{
	0xAA, 0x3A, 0xC0, 0x7F, 0xA7, 0x46, 0xDB, 0x18,
	0x2E, 0xAC, 0x69, 0x8F, 0x8D, 0x41, 0x7F, 0x5A,
}

// ChipsetACModuleInformation represents Chipset AC Module Information Table parts for all versions
type ChipsetACModuleInformation struct {
	UUID            [16]byte
	ChipsetACMType  uint8
	Version         uint8
	Length          uint16
	ChipsetIDList   uint32
	OsSinitDataVer  uint32
	MinMleHeaderVer uint32
	Capabilities    uint32
	AcmVersion      uint8
	AcmRevision     [3]uint8
	ProcessorIDList uint32
}

// ChipsetACModuleInformationV5 represents Chipset AC Module Information Table for version >= 5
type ChipsetACModuleInformationV5 struct {
	Base        ChipsetACModuleInformation
	TPMInfoList uint32
}
