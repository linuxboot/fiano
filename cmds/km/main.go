// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// fspinfo prints FSP header information.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntkey"
	"github.com/linuxboot/fiano/pkg/log"
)

var (
	flagJSON = flag.Bool("j", false, "Output as JSON")
)

func main() {
	flag.Parse()
	if flag.Arg(0) == "" {
		log.Fatalf("missing file name")
	}
	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatalf("cannot read input file: %v", err)
	}

	KEYMMagic := []byte("__KEYM__")
	offset := bytes.Index(data, KEYMMagic)
	if offset == -1 {
		log.Fatalf("no %v magic (%x) found", string(KEYMMagic), KEYMMagic)
	}

	m := cbntkey.Manifest{}
	_, err = m.ReadFrom(bytes.NewReader(data))
	if err != nil {
		log.Fatalf("%v", err)
	}

	j, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Fatalf("cannot marshal JSON: %v", err)
	}
	if *flagJSON {
		fmt.Println(string(j))
	} else {
		fmt.Print(m.PrettyString(0, true))
	}
}
