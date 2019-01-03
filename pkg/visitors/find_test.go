// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"testing"

	"github.com/linuxboot/fiano/pkg/uefi"
)

func TestFind(t *testing.T) {
	f := parseImage(t)
	results := find(t, f, testGUID)

	// We expect one match
	if len(results) != 1 {
		t.Fatalf("got %d matches; expected 1", len(results))
	}
}

func TestFindExactlyOne(t *testing.T) {
	f := parseImage(t)
	_, err := FindExactlyOne(f, func(_ uefi.Firmware) bool {
		return true
	})
	if err == nil {
		t.Errorf("should have an error from matching too many, got no error")
	}

	_, err = FindExactlyOne(f, func(_ uefi.Firmware) bool {
		return false
	})
	if err == nil {
		t.Errorf("should have an error from matching none, got no error")
	}

	pred := FindFileTypePredicate(uefi.FVFileTypeDXECore)
	res, err := FindExactlyOne(f, pred)
	if err != nil {
		t.Fatalf("should match one Dxe Core, got: %v", err)
	}

	dxecore, ok := res.(*uefi.File)
	if !ok {
		t.Fatalf("result was not a file, got %T", res)
	}
	if dxecore.Header.Type != uefi.FVFileTypeDXECore {
		t.Errorf("result was not the correct file type! got %v", dxecore.Header.Type)
	}
}

func TestFindDXEFV(t *testing.T) {
	f := parseImage(t)
	fv, err := FindDXEFV(f)
	if err != nil {
		t.Fatalf("should return one dxe FV, got err: %v", err)
	}

	if fv == nil {
		t.Fatalf("got nil fv")
	}

	// Search through files for dxecore
	var found bool
	for _, v := range fv.Files {
		if v.Header.Type == uefi.FVFileTypeDXECore {
			found = true
		}
	}

	if !found {
		t.Errorf("unable to find DXECore in fv's files, this is probably not the DXE firmware volume")
	}
}
