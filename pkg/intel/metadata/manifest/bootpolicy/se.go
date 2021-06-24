//go:generate manifestcodegen

package bootpolicy

import (
	"fmt"
	"math"
	"time"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
)

// SE is an IBB segments element
//
// PrettyString: IBB Segments Element
type SE struct {
	StructInfo `id:"__IBBS__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
	Reserved0  [1]byte   `require:"0" json:"seReserved0,omitempty"`
	SetNumber  uint8     `require:"0" json:"seSetNumber,omitempty"`
	Reserved1  [1]byte   `require:"0" json:"seReserved1,omitempty"`
	PBETValue  PBETValue `json:"sePBETValue"`
	Flags      SEFlags   `json:"seFlags"`

	// IBBMCHBAR <TO BE DOCUMENTED>
	// PrettyString: IBB MCHBAR
	IBBMCHBAR uint64 `json:"seIBBMCHBAR"`

	// VTdBAR <TO BE DOCUMENTED>
	// PrettyString: VT-d BAR
	VTdBAR uint64 `json:"seVTdBAR"`

	// DMAProtBase0 <TO BE DOCUMENTED>
	// PrettyString: DMA Protection 0 Base Address
	DMAProtBase0 uint32 `json:"seDMAProtBase0"`

	// DMAProtLimit0 <TO BE DOCUMENTED>
	// PrettyString: DMA Protection 0 Limit Address
	DMAProtLimit0 uint32 `json:"seDMAProtLimit0"`

	// DMAProtBase1 <TO BE DOCUMENTED>
	// PrettyString: DMA Protection 1 Base Address
	DMAProtBase1 uint64 `json:"seDMAProtBase1"`

	// DMAProtLimit1 <TO BE DOCUMENTED>
	// PrettyString: DMA Protection 2 Limit Address
	DMAProtLimit1 uint64 `json:"seDMAProtLimit1"`

	PostIBBHash manifest.HashStructure `json:"sePostIBBHash"`

	IBBEntryPoint uint32 `json:"seIBBEntry"`

	DigestList manifest.HashList `json:"seDigestList"`

	OBBHash manifest.HashStructure `json:"seOBBHash"`

	Reserved2 [3]byte `require:"0" json:"seReserved2,omitempty"`

	IBBSegments []IBBSegment `countType:"uint8" json:"seIBBSegments,omitempty"`
}

// PBETValue <TO BE DOCUMENTED>
type PBETValue uint8

// PBETValue returns the raw value of the timer setting.
func (pbet PBETValue) PBETValue() uint8 {
	return uint8(pbet) & 0x0f
}

// Duration returns the value as time.Duration.
func (pbet PBETValue) Duration() time.Duration {
	v := pbet.PBETValue()
	if v == 0 {
		return math.MaxInt64
	}
	return time.Second * time.Duration(5+v)
}

// SetDuration sets the value using standard time.Duration as the input.
func (pbet *PBETValue) SetDuration(duration time.Duration) time.Duration {
	v := duration.Nanoseconds()/time.Second.Nanoseconds() - 5
	if v <= 0 {
		v = 1
	}
	if v >= 16 {
		v = 0
	}
	*pbet = PBETValue(v)

	return pbet.Duration()
}

// SEFlags <TO BE DOCUMENTED>
type SEFlags uint32

// Reserved0 <TO BE DOCUMENTED>
func (flags SEFlags) Reserved0() uint32 {
	return uint32(flags & 0xffffffe0)
}

// SupportsTopSwapRemediation <TO BE DOCUMENTED>
//
// PrettyString-true:  BIOS supports Top Swap remediation action
// PrettyString-false: BIOS does not support Top Swap remediation action
func (flags SEFlags) SupportsTopSwapRemediation() bool {
	return flags&0x10 != 0
}

// TPMFailureLeavesHierarchiesEnabled <TO BE DOCUMENTED>
//
// PrettyString-true:  Leave Hierarchies enabled. Cap all PCRs on failure.
// PrettyString-false: Do not leave enabled. Disable all Hierarchies or deactivate on failure.
func (flags SEFlags) TPMFailureLeavesHierarchiesEnabled() bool {
	return flags&0x08 != 0
}

// AuthorityMeasure <TO BE DOCUMENTED>
//
// PrettyString-true:  Extend Authority Measurements into the Authority PCR 7
// PrettyString-false: Do not extend into the Authority PCR 7
func (flags SEFlags) AuthorityMeasure() bool {
	return flags&0x04 != 0
}

// Locality3Startup <TO BE DOCUMENTED>
//
// PrettyString-true:  Issue TPM Start-up from Locality 3
// PrettyString-false: Disabled
func (flags SEFlags) Locality3Startup() bool {
	return flags&0x02 != 0
}

// DMAProtection <TO BE DOCUMENTED>
//
// PrettyString-true:  Enable DMA Protection
// PrettyString-false: Disable DMA Protection
func (flags SEFlags) DMAProtection() bool {
	return flags&0x01 != 0
}

// IBBSegment defines a single IBB segment
type IBBSegment struct {
	Reserved [2]byte `require:"0" json:"ibbSegReserved"`
	Flags    uint16  `json:"ibbSegFlags"`
	Base     uint32  `json:"ibbSegBase"`
	Size     uint32  `json:"ibbSegSize"`
}

// CachingType <TO BE DOCUMENTED>
type CachingType uint8

// <TO BE DOCUMENTED>
const (
	CachingTypeWriteProtect = CachingType(iota)
	CachingTypeWriteBack
	CachingTypeReserved0
	CachingTypeReserved1
)

// String implements fmt.Stringer.
func (c CachingType) String() string {
	switch c {
	case CachingTypeWriteProtect:
		return "write_protect"
	case CachingTypeWriteBack:
		return "write_back"
	case CachingTypeReserved0:
		return "value_0x02"
	case CachingTypeReserved1:
		return "value_0x03"
	}
	return fmt.Sprintf("unexpected_value_0x%02X", uint8(c))
}
