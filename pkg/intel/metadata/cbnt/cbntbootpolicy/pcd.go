// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package cbntbootpolicy

// PCD holds various Platform Config Data.
type PCD struct {
	StructInfo `id:"__PCDS__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
	Reserved0  [2]byte `json:"pcdReserved0,omitempty"`
	Data       []byte  `json:"pcdData"`
}
