// +build !manifestcodegen
//
// To avoid errors "type ChipsetACModuleInformation has no field or method ReadFrom"
// with a build tag "!manifestcodegen"

package manifest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// ParseChipsetACModuleInformation parses Chipset AC Module Information Table according to the version
func ParseChipsetACModuleInformation(r io.Reader) (int64, ChipsetACModuleInformationV5, error) {
	var result ChipsetACModuleInformationV5
	total, err := result.Base.ReadFrom(r)
	if bytes.Compare(result.Base.UUID[:], chipsetACModuleInformationSignature) != 0 {
		return 0, ChipsetACModuleInformationV5{}, fmt.Errorf(
			"incorrect UUID [%x], expected: [%x]", result.Base.UUID, chipsetACModuleInformationSignature)
	}
	if err != nil {
		return total, result, err
	}
	if result.Base.Version < 5 {
		return total, result, nil
	}
	err = binary.Read(r, binary.LittleEndian, &result.TPMInfoList)
	total += int64(binary.Size(result.TPMInfoList))
	return total, result, err
}
