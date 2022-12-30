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
