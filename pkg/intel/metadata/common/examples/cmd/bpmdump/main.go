// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/bootpolicy"
)

func assertNoError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	f, err := os.Open(os.Args[1])
	assertNoError(err)

	m := &bootpolicy.Manifest{}
	_, err = m.ReadFrom(f)
	assertNoError(err)

	fmt.Printf("%s", m.PrettyString(0, true))
}
