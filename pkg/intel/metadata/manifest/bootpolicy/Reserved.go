// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package bootpolicy

// Reserved is reducted
type Reserved struct {
	StructInfo   `id:"__PFRS__" version:"0x21" var0:"0" var1:"uint16(s.TotalSize())"`
	ReservedData [32]byte `json:"ReservedData"`
}
