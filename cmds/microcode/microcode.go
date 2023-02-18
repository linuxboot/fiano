// Copyright 2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"github.com/linuxboot/fiano/pkg/intel/microcode"
	flag "github.com/spf13/pflag"
)

func main() {
	flag.Parse()

	a := flag.Args()
	if len(a) != 1 {
		log.Fatal("Usage: microcode <microcode-file>")
	}

	f, err := os.Open(a[0])
	if err != nil {
		log.Fatal(err)
	}
	b := bufio.NewReader(f)

	for {
		_, err = b.Peek(microcode.DefaultTotalSize)
		if err != nil {
			break
		}
		m, err := microcode.ParseIntelMicrocode(b)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(m)
	}
}
