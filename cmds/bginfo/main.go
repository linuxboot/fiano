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

	"github.com/linuxboot/fiano/pkg/intel/metadata/bg/bgbootpolicy"
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
		log.Fatalf("cannot read input file: %x", err)
	}

	acbpMagic := []byte("__ACBP__")
	// __IBBS__ also seen in the next 16 bytes; not sure what that is
	offset := bytes.Index(data, acbpMagic)
	if offset == -1 {
		log.Fatalf("no %v (%x) magic found", string(acbpMagic), acbpMagic)
	}

	m := bgbootpolicy.Manifest{}
	if _, err = m.ReadFrom(bytes.NewReader(data[offset:])); err != nil {
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
