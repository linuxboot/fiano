// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"os"
	"testing"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/uefi"
)

var (
	testDXE1 = guid.MustParse("93B80004-9FB3-11D4-9A3A-0090273FC14D")
	testDXE2 = guid.MustParse("4B28E4C7-FF36-4E10-93CF-A82159E777C5")
	testDXE3 = guid.MustParse("C8339973-A563-4561-B858-D8476F9DEFC4")
	testDXE4 = guid.MustParse("378D7B65-8DA9-4773-B6E4-A47826A833E1")
	testDXE5 = guid.MustParse("33CB97AF-6C33-4C42-986B-07581FA366D4")
)

func contains(t *testing.T, f uefi.Firmware, g *guid.GUID) bool {
	return len(find(t, f, g)) > 0
}

func TestDXECleaner(t *testing.T) {
	// This test to see if an image "boots" by looking for fake dependencies
	// between the DXEs.
	testDXEDependencies := func(f uefi.Firmware) (bool, error) {
		// Dependencies
		return contains(t, f, testDXE5) &&
			(!contains(t, f, testDXE5) || contains(t, f, testDXE4)) &&
			(!contains(t, f, testDXE2) || contains(t, f, testDXE1)) &&
			(!contains(t, f, testDXE3) || contains(t, f, testDXE2)), nil
	}

	// Parse image and run the visitor.
	f := parseImage(t)
	dxeCleaner := DXECleaner{
		Test: testDXEDependencies,
		W:    os.Stdout,
	}
	if err := dxeCleaner.Run(f); err != nil {
		t.Fatal(err)
	}

	// Check that the correct DXEs remain.
	for _, d := range []*guid.GUID{testDXE1, testDXE2, testDXE3} {
		if contains(t, f, d) {
			t.Errorf("expected %v to be deleted", d)
		}
	}
	for _, d := range []*guid.GUID{testDXE4, testDXE5} {
		if !contains(t, f, d) {
			t.Errorf("expected %v to be remain", d)
		}
	}
}
