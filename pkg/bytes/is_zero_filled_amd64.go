// +build amd64

package bytes

import (
	"reflect"
	"unsafe"
)

// IsZeroFilled returns true if b consists of zeros only.
func IsZeroFilled(b []byte) bool {
	hdr := (*reflect.SliceHeader)((unsafe.Pointer)(&b))
	data := hdr.Data
	length := hdr.Len
	if data&0x07 != 0 {
		// the data is not aligned, fallback to a simple way
		return isZeroFilledSimple(b)
	}
	dataEnd := hdr.Data + uintptr(length)
	dataWordsEnd := dataEnd & ^uintptr(0x07)
	for ; data < dataWordsEnd; data += 8 {
		if *(*uint64)(unsafe.Pointer(data)) != 0 {
			return false
		}
	}
	for ; data < dataEnd; data++ {
		if *(*uint8)(unsafe.Pointer(data)) != 0 {
			return false
		}
	}
	return true
}
