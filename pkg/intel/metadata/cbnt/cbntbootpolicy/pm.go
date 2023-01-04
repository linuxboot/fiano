// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package cbntbootpolicy

// PM is the platform manufacturer data element
type PM struct {
	StructInfo `id:"__PMDA__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
	Reserved0  [2]byte `require:"0" json:"pcReserved0,omitempty"`
	Data       []byte  `json:"pcData"`
}
