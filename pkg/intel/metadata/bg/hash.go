// Copyright 2017-2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package bg

// HashStructure describes a digest.
type HashStructure struct {
	HashAlg    Algorithm `default:"0x10" json:"hsAlg"`
	HashBuffer []byte    `json:"hsBuffer"`
}

type HashStructureFill struct {
	HashAlg    Algorithm `default:"0x0b" json:"hsAlg"`
	HashBuffer []byte    `countValue:"hashSize()" prettyValue:"hashSizePrint()" json:"hsBuffer"`
}

func (a Algorithm) size() uint16 {
	switch a {
	case AlgUnknown:
		return 0
	case AlgNull:
		return 0
	case AlgSHA1:
		return 20
	case AlgSHA256:
		return 32
	default:
		return 0
	}
}

func (h HashStructureFill) hashSize() uint16 {
	const hashSizeFieldLen = 2
	if h.HashAlg.IsNull() {
		// Evil hack, more investigation needed
		return AlgSHA256.size() + hashSizeFieldLen
	} else {
		return h.HashAlg.size() + hashSizeFieldLen
	}
}

func (h HashStructureFill) hashSizePrint() interface{} {
	if h.HashAlg.IsNull() {
		// Evil hack, more investigation needed
		return make([]byte, AlgSHA256.size())
	} else {
		return h.HashBuffer
	}
}
