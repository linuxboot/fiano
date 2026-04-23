// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cbntkey provides Key Manifest representation.
package cbntkey

import (
	"crypto"
	"fmt"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
)

type Manifest interface {
	ValidateBPMKey(bpmKS cbnt.KeySignature) error
	SetSignature(
		algo cbnt.Algorithm,
		hashAlgo cbnt.Algorithm,
		privKey crypto.Signer,
		signedData []byte,
	) error
	cbnt.Element
	Print()
}

func NewManifest(bgv cbnt.BootGuardVersion) (Manifest, error) {
	switch bgv {
	case cbnt.Version10:
		s := &BGManifest{}
		s.StructInfoBG = *cbnt.NewStructInfo(cbnt.Version10).(*cbnt.StructInfoBG)
		s.Version = 0x10
		copy(s.ID[:], []byte(cbnt.StructureIDManifest))
		s.KeyAndSignature = *cbnt.NewKeySignature()
		return s, nil
	case cbnt.Version20, cbnt.Version21:
		s := &CBnTManifest{}
		s.StructInfoCBNT = *cbnt.NewStructInfo(cbnt.Version20).(*cbnt.StructInfoCBNT)
		s.Version = 0x21
		copy(s.ID[:], []byte(cbnt.StructureIDManifest))
		s.KeyAndSignature = *cbnt.NewKeySignature()
		return s, nil
	default:
		// This will never be the case in internal usage of NewManifest,
		// though out of principle the error handling is here
		return nil, fmt.Errorf("version not supported")
	}
}
