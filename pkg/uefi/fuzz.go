// Copyright 2020 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build gofuzz

package uefi

import (
	"log"
)

// go get github.com/dvyukov/go-fuzz/go-fuzz
// go get github.com/dvyukov/go-fuzz/go-fuzz-build
//
// mkdir fuzz
// go-fuzz-build
// go-fuzz -bin uefi-fuzz.zip -workdir fuzz

type nopWriter struct{}

func (n *nopWriter) Write(_ []byte) (int, error) { return 0, nil }

func init() {
	//speed up logging
	log.SetFlags(0)
	log.SetOutput(&nopWriter{})
}

const (
	ICK int = iota - 1
	MEH
	WOW
)

//	func Parse(buf []byte) (Firmware, error)
func Fuzz(b []byte) int {
	//initialize, since something could have changed the polarity
	Attributes = ROMAttributes{ErasePolarity: poisonedPolarity}
	_, err := Parse(b)
	if err == nil {
		return MEH
	}
	return WOW
}
