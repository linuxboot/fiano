// Copyright 2017-2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package bgbootpolicy

import (
	"bytes"
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

func (m *Manifest) ValidateBPMKey(bpmKS bg.KeySignature) error {
	h, err := m.BPKey.HashAlg.Hash()
	if err != nil {
		return fmt.Errorf("invalid hash algo %v: %w", m.BPKey.HashAlg, err)
	}

	if len(m.BPKey.HashBuffer) != h.Size() {
		return fmt.Errorf("invalid hash lenght: actual:%d expected:%d", len(m.BPKey.HashBuffer), h.Size())
	}

	switch bpmKS.Key.KeyAlg {
	case bg.AlgRSA:
		if _, err := h.Write(bpmKS.Key.Data[4:]); err != nil {
			return fmt.Errorf("unable to hash: %w", err)
		}
	default:
		return fmt.Errorf("unsupported key algorithm: %v", bpmKS.Key.KeyAlg)
	}
	digest := h.Sum(nil)

	if !bytes.Equal(m.BPKey.HashBuffer, digest) {
		return fmt.Errorf("BPM key hash does not match the one in KM: actual:%X != in-KM:%X (hash algo: %v)", digest, m.BPKey.HashBuffer, m.BPKey.HashAlg)
	}

	return nil
}
