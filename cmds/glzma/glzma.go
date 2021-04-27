// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// glzma compresses and decompresses in the same manner as EDK2's LzmaCompress.
//
// Synopsis:
//     glzma -o OUTPUT_FILE (-d|-e) [-f86] INPUT_FILE
//
// Options:
//     -d: decode
//     -e: encode
//     -f86: Use the x86 branch/call/jump filter. See `man xz` for more information.
//     -o OUTPUT_FILE: output file
package main

import (
	"flag"
	"io/ioutil"

	"github.com/linuxboot/fiano/pkg/compression"
	"github.com/linuxboot/fiano/pkg/log"
)

var (
	d   = flag.Bool("d", false, "decode")
	e   = flag.Bool("e", false, "encode")
	f86 = flag.Bool("f86", false, "use x86 extension")
	o   = flag.String("o", "", "output file")
)

func main() {
	flag.Parse()

	if *d == *e {
		log.Fatalf("either decode (-d) or encode (-e) must be set")
	}
	if *o == "" {
		log.Fatalf("output file must be set")
	}
	if flag.NArg() != 1 {
		log.Fatalf("expected one input file")
	}

	var compressor compression.Compressor
	if *f86 {
		compressor = compression.CompressorFromGUID(&compression.LZMAX86GUID)
	} else {
		compressor = compression.CompressorFromGUID(&compression.LZMAGUID)
	}

	var op func([]byte) ([]byte, error)
	if *d {
		op = compressor.Decode
	} else {
		op = compressor.Encode
	}

	in, err := ioutil.ReadFile(flag.Args()[0])
	if err != nil {
		log.Fatalf("%v", err)
	}
	out, err := op(in)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if err := ioutil.WriteFile(*o, out, 0666); err != nil {
		log.Fatalf("%v", err)
	}
}
