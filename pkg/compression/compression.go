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
	"os/exec"

	"github.com/linuxboot/fiano/pkg/guid"
)

var xzPath = flag.String("xzPath", "xz", "Path to system xz command used for lzma encoding. If unset, an internal lzma implementation is used.")

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
	ZLIBGUID    = *guid.MustParse("CE3233F5-2CD6-4D87-9152-4A238BB6D1C4")
)

// CompressorFromGUID returns a Compressor for the corresponding GUIDed Section.
func CompressorFromGUID(guid *guid.GUID) Compressor {
	// Default to system xz command for lzma encoding; if not found, use an
	// internal lzma implementation.
	var lzma Compressor
	if _, err := exec.LookPath(*xzPath); err == nil {
		lzma = &SystemLZMA{*xzPath}
	} else {
		lzma = &LZMA{}
	}
	switch *guid {
	case LZMAGUID:
		return lzma
	case LZMAX86GUID:
		// Alternatively, the -f86 argument could be passed
		// into xz. It does not make much difference because
		// the x86 filter is not the bottleneck.
		return &LZMAX86{lzma}
	case ZLIBGUID:
		return &ZLIB{}
	}
	return nil
}
