// Copyright 2017-2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package key

import (
	"crypto"
	"fmt"

	"github.com/linuxboot/fiano/pkg/intel/metadata/bg"
)

type Manifest struct {
	bg.StructInfo   `id:"__KEYM__" version:"0x10"`
	KMVersion       uint8            `json:"kmVersion"`
	KMSVN           bg.SVN           `json:"kmSVN"`
	KMID            uint8            `json:"kmID"`
	BPKey           bg.HashStructure `json:"kmBPKey"`
	KeyAndSignature bg.KeySignature  `json:"kmKeySignature"`
}

func (m *Manifest) SetSignature(
	algo bg.Algorithm,
	privKey crypto.Signer,
	signedData []byte,
) error {
	err := m.KeyAndSignature.SetSignature(algo, privKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to set the signature: %w", err)
	}

	return nil
}
