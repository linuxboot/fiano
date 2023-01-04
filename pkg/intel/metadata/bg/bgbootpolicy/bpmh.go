// Copyright 2017-2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package bgbootpolicy

import "github.com/linuxboot/fiano/pkg/intel/metadata/bg"

type BPMH struct {
	StructInfo `id:"__ACBP__" version:"0x10"`

	HdrStructVersion uint8 `json:"HdrStructVersion"`

	PMBPMVersion uint8 `json:"bpmhRevision"`

	// PrettyString: BPM SVN
	BPMSVN bg.SVN `json:"bpmhSNV"`
	// PrettyString: ACM SVN Auth
	ACMSVNAuth bg.SVN `json:"bpmhACMSVN"`

	Reserved0 [1]byte `require:"0" json:"bpmhReserved0,omitempty"`

	NEMDataStack Size4K `json:"bpmhNEMStackSize"`
}

// Size4K is a size in units of 4096 bytes.
type Size4K uint16

// InBytes returns the size in bytes.
func (s Size4K) InBytes() uint32 {
	return uint32(s) * 4096
}

// NewSize4K returns the given size as multiple of 4K
func NewSize4K(size uint32) Size4K {
	return Size4K(size / 4096)
}
