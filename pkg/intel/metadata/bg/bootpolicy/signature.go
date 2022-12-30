// Copyright 2017-2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package bootpolicy

import "github.com/linuxboot/fiano/pkg/intel/metadata/bg"

// Signature contains the signature of the BPM.
type Signature struct {
	StructInfo      `id:"__PMSG__" version:"0x10"`
	bg.KeySignature `json:"sigKeySignature"`
}
