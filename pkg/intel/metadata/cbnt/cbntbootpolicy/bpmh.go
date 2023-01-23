// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package cbntbootpolicy

import (
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
)

// BPMH is the header of boot policy manifest
type BPMH struct {
	StructInfo `id:"__ACBP__" version:"0x23" var0:"0x20" var1:"uint16(s.TotalSize())"`

	KeySignatureOffset uint16 `json:"bpmhKeySignatureOffset"`

	BPMRevision uint8 `json:"bpmhRevision"`

	// BPMSVN is BPM security version number
	//
	// PrettyString: BPM SVN
	BPMSVN cbnt.SVN `json:"bpmhSNV"`

	// ACMSVNAuth is authorized ACM security version number
	//
	// PrettyString: ACM SVN Auth
	ACMSVNAuth cbnt.SVN `json:"bpmhACMSVN"`

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
