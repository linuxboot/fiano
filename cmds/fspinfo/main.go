// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// fspinfo prints FSP header information.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/linuxboot/fiano/pkg/fsp"
	"github.com/linuxboot/fiano/pkg/log"
	"github.com/linuxboot/fiano/pkg/uefi"
)

var (
	flagJSON = flag.Bool("j", false, "Output as JSON")
)

// extractFSPHeader decapsulates an FSP header as described by the FSP specification.
// The FSP files from intel contain various components (e.g. FSP-M, FSP-T, FSP-S),
// each contained in a firmware volume.
// Each FSP component has an FSP_INFO_HEADER in the first FFS file in the first firmware
// volume.
// See https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/fsp-architecture-spec-v2.pdf chapter 4.

// TODO extract the remaining firmware volumes too
func extractFirstFSPHeader(b []byte) (*fsp.InfoHeaderRev3, error) {
	fv, err := uefi.NewFirmwareVolume(b, 0, false)
	if err != nil {
		return nil, fmt.Errorf("cannot parse Firmware Volume: %v", err)
	}
	if len(fv.Files) < 1 {
		return nil, errors.New("firmware Volume has no files")
	}
	file := fv.Files[0]
	sec, err := uefi.NewSection(file.Buf()[file.DataOffset:], 0)
	if err != nil {
		return nil, fmt.Errorf("cannot parse section: %v", err)
	}
	// the section header size is 4, so skip it to get the data
	hdr, err := fsp.NewInfoHeader(sec.Buf()[4:])
	if err != nil {
		return nil, fmt.Errorf("cannot parse FSP Info Header: %v", err)
	}
	return hdr, nil
}

func main() {
	flag.Parse()
	if flag.Arg(0) == "" {
		log.Fatalf("missing file name")
	}
	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatalf("cannot read input file: %v", err)
	}
	hdr, err := extractFirstFSPHeader(data)
	if err != nil {
		log.Fatalf("%v", err)
	}

	j, err := json.MarshalIndent(hdr, "", "    ")
	if err != nil {
		log.Fatalf("cannot marshal JSON: %v", err)
	}
	if *flagJSON {
		fmt.Println(string(j))
	} else {
		fmt.Print(hdr.Summary())
	}
}
