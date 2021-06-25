package manifest

import (
	"encoding/binary"
	"fmt"
	"io"
)

const PSPBootloaderCookie = 0x31535024 // "$PS1"

type FirmwareVersion [4]byte

func (v FirmwareVersion) String() string {
	return fmt.Sprintf("%x.%x.%x.%x", v[3], v[2], v[1], v[0])
}

// PSPHeader represents a header of each firmware binary
// See: https://doc.coreboot.org/soc/amd/psp_integration.html
type PSPHeader struct {
	Reserved1 [16]byte
	Cookie    uint32
	Reserved2 [76]byte
	Version   FirmwareVersion
	Reserved3 [156]byte
}

func ParsePSPHeader(r io.Reader) (*PSPHeader, error) {
	var result PSPHeader
	if err := binary.Read(r, binary.LittleEndian, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
