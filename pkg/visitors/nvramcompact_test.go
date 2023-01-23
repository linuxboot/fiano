// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"os"
	"testing"

	"github.com/linuxboot/fiano/pkg/uefi"
)

func TestNVRamCompact(t *testing.T) {
	path := "../../integration/roms/nvartest/"

	tmpDir, err := os.MkdirTemp("", "section-test")

	if err != nil {
		t.Fatalf("could not create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	var parsedRoot uefi.Firmware
	// Call ParseDir
	pd := ParseDir{BasePath: path}
	if parsedRoot, err = pd.Parse(); err != nil {
		t.Fatal(err)
	}
	// Assemble the tree from the bottom up
	a := Assemble{}
	if err = a.Run(parsedRoot); err != nil {
		t.Fatal(err)
	}

	// initial count
	count := &Count{}
	if err = count.Run(parsedRoot); err != nil {
		t.Fatal(err)
	}

	want := 6
	got := count.FirmwareTypeCount["NVar"]
	if got != want {
		t.Fatalf("counted %d NVar, want %d", got, want)
	}

	// Compact
	compact := &NVRamCompact{}
	if err = compact.Run(parsedRoot); err != nil {
		t.Fatal(err)
	}

	// count
	if err = count.Run(parsedRoot); err != nil {
		t.Fatal(err)
	}

	want = 5
	got = count.FirmwareTypeCount["NVar"]
	if got != want {
		t.Fatalf("counted %d NVar, want %d", got, want)
	}

}
