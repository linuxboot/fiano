// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package cbntbootpolicy

import (
	"fmt"
	"time"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
)

// TXT is the TXT element
type TXT struct {
	StructInfo      `id:"__TXTS__" version:"0x21" var0:"0" var1:"uint16(s.TotalSize())"`
	Reserved0       [1]byte          `require:"0" json:"txtReserved0,omitempty"`
	SetNumber       [1]byte          `require:"0" json:"txtSetNumer,omitempty"`
	SInitMinSVNAuth uint8            `default:"0" json:"txtSVN"`
	Reserved1       [1]byte          `require:"0" json:"txtReserved1,omitempty"`
	ControlFlags    TXTControlFlags  `json:"txtFlags"`
	PwrDownInterval Duration16In5Sec `json:"txtPwrDownInterval"`
	// PrettyString: PTT CMOS Offset 0
	PTTCMOSOffset0 uint8 `default:"126" json:"txtPTTCMOSOffset0"`
	// PrettyString: PTT CMOS Offset 1
	PTTCMOSOffset1 uint8   `default:"127" json:"txtPTTCMOSOffset1"`
	ACPIBaseOffset uint16  `default:"0x400" json:"txtACPIBaseOffset,omitempty"`
	Reserved2      [2]byte `json:"txtReserved2,omitempty"`
	// PrettyString: ACPI MMIO Offset
	PwrMBaseOffset uint32        `default:"0xFE000000" json:"txtPwrMBaseOffset,omitempty"`
	DigestList     cbnt.HashList `json:"txtDigestList"`
	Reserved3      [3]byte       `require:"0" json:"txtReserved3,omitempty"`

	SegmentCount uint8 `require:"0" json:"txtSegmentCount,omitempty"`
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
