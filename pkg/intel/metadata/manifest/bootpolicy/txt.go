//go:generate manifestcodegen

package bootpolicy

import (
	"fmt"
	"time"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
)

type TXT struct {
	StructInfo      `id:"__TXTS__" version:"0x21" var0:"0" var1:"uint16(s.TotalSize())"`
	Reserved0       [1]byte          `require:"0" json:"txt_Reserved0,omitempty"`
	SetNumber       [1]byte          `require:"0" json:"txt_SetNumer,omitempty"`
	SInitMinSVNAuth uint8            `json:"txt_SVN"`
	Reserved1       [1]byte          `require:"0" json:"txt_Reserved1,omitempty"`
	ControlFlags    TXTControlFlags  `json:"txt_Flags"`
	PwrDownInterval Duration16In5Sec `json:"tx_PwrDownInterval"`
	// PrettyString: PTT CMOS Offset 0
	PTTCMOSOffset0 uint8 `default:"126" json:"txt_PTTCMOSOffset0"`
	// PrettyString: PTT CMOS Offset 1
	PTTCMOSOffset1 uint8   `default:"127" json:"txt_PTTCMOSOffset1"`
	ACPIBaseOffset uint16  `default:"0x400" json:"txt_ACPIBaseOffset,omitempty"`
	Reserved2      [2]byte `json:"txt_Reserved2,omitempty"`
	// PrettyString: ACPI MMIO Offset
	PwrMBaseOffset uint32            `default:"0xFE000000" json:"txt_PwrMBaseOffset,omitempty"`
	DigestList     manifest.HashList `json:"txt_DigestList"`
	Reserved3      [3]byte           `require:"0" json:"txt_Reserved3,omitempty"`

	SegmentCount uint8 `require:"0" json:"txt_SegmentCount,omitempty"`
}

// Duration16In5Sec exports the custom type Duration16In5Sec
type Duration16In5Sec uint16

// Duration calculates a given time in multiple of 5 seconds.
func (d Duration16In5Sec) Duration() time.Duration {
	return time.Second * 5 * time.Duration(d)
}

func (d Duration16In5Sec) String() string {
	if d == 0 {
		return "0 (infinite)"
	}
	return fmt.Sprintf("%d (%s)", d, d.Duration().String())
}
