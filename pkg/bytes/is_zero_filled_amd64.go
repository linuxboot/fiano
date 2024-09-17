// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build amd64
// +build amd64

package bytes

import (
	"unsafe"
)

// IsZeroFilled returns true if b consists of zeros only.
func IsZeroFilled(b []byte) bool {
	length := len(b)
	if length == 0 {
		return true
	}
	var data = unsafe.Pointer(&b[0])

	if uintptr(data)&0x07 != 0 {
		// the data is not aligned, fallback to a simple way
		return isZeroFilledSimple(b)
	}

	dataEnd := uintptr(data) + uintptr(length)
	dataWordsEnd := uintptr(dataEnd) & ^uintptr(0x07)
	// example:
	//
	//     012345678901234567
	//     wwwwwwwwWWWWWWWWtt : w -- word 0; W -- word 1; t -- tail
	//                     ^
	//                     |
	//                     +-- dataWordsEnd
	for ; uintptr(data) < dataWordsEnd; data = unsafe.Pointer(uintptr(data) + 8) {
		if *(*uint64)(data) != 0 {
			return false
		}
	}
	for ; uintptr(data) < dataEnd; data = unsafe.Pointer(uintptr(data) + 1) {
		if *(*uint8)(data) != 0 {
			return false
		}
	}
	return true
}
