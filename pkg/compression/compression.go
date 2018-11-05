// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package compression implements reading and writing of compressed files.
//
// This package is specifically designed for the LZMA formats used by popular UEFI
// implementations.
package compression

import (
	"flag"

	"github.com/linuxboot/fiano/pkg/guid"
)

var xzPath = flag.String("xzPath", "", "Path to system xz command used for lzma encoding. If unset, an internal lzma implementation is used.")

// Compressor defines a single compression scheme (such as LZMA).
type Compressor interface {
	// Name is typically the name of a class.
	Name() string

	// Decode and Encode obey "x == Decode(Encode(x))".
	Decode(encodedData []byte) ([]byte, error)
	Encode(decodedData []byte) ([]byte, error)
}

// Well-known GUIDs for GUIDed sections containing compressed data.
var (
	LZMAGUID    = *guid.MustParse("EE4E5898-3914-4259-9D6E-DC7BD79403CF")
	LZMAX86GUID = *guid.MustParse("D42AE6BD-1352-4BFB-909A-CA72A6EAE889")
)

// CompressorFromGUID returns a Compressor for the corresponding GUIDed Section.
func CompressorFromGUID(guid *guid.GUID) Compressor {
	switch *guid {
	case LZMAGUID:
		if *xzPath != "" {
			return &SystemLZMA{*xzPath}
		}
		return &LZMA{}
	case LZMAX86GUID:
		if *xzPath != "" {
			// Alternatively, the -f86 argument could be passed
			// into xz. It does not make much difference because
			// the x86 filter is not the bottleneck.
			return &LZMAX86{&SystemLZMA{*xzPath}}
		}
		return &LZMAX86{&LZMA{}}
	}
	return nil
}
