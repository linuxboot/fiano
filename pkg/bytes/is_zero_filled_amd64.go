// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build amd64
// +build amd64

package bytes

import (
	"reflect"
	"unsafe"
)

// IsZeroFilled returns true if b consists of zeros only.
func IsZeroFilled(b []byte) bool {
	hdr := (*reflect.SliceHeader)((unsafe.Pointer)(&b))
	data := unsafe.Pointer(hdr.Data)
	length := hdr.Len
	if uintptr(data)&0x07 != 0 {
		// the data is not aligned, fallback to a simple way
		return isZeroFilledSimple(b)
	}
	dataEnd := hdr.Data + uintptr(length)
	dataWordsEnd := dataEnd & ^uintptr(0x07)
	for ; uintptr(data) < dataWordsEnd; data = unsafe.Pointer(uintptr(data) + 8) {
		if *(*uint64)(data) != 0 {
			return false
		}
	}
	for ; uintptr(data) < dataWordsEnd; data = unsafe.Pointer(uintptr(data) + 1) {
		if *(*uint8)(data) != 0 {
			return false
		}
	}
	return true
}
