// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// This GUID exists somewhere in the OVMF image.
var testGUID = guid.MustParse("DF1CCEF6-F301-4A63-9661-FC6030DCC880")

func parseImage(t *testing.T) uefi.Firmware {
	image, err := ioutil.ReadFile("../../integration/roms/OVMF.rom")
	if err != nil {
		t.Fatal(err)
	}
	parsedRoot, err := uefi.Parse(image)
	if err != nil {
		t.Fatal(err)
	}
	return parsedRoot
}

func find(t *testing.T, f uefi.Firmware, guid *guid.GUID) []uefi.Firmware {
	find := &Find{
		Predicate: FindFileGUIDPredicate(*guid),
	}
	if err := find.Run(f); err != nil {
		t.Fatal(err)
	}
	return find.Matches
}

func comment(t *testing.T, f uefi.Firmware) []uefi.Firmware {
	var b bytes.Buffer
	c := &Comment{W: &b, s: "hi"}
	if err := c.Run(f); err != nil {
		t.Fatal(err)
	}
	if b.String() != "hi\n" {
		t.Fatalf("Comment: go %q, wanted 'hi'", b.String())
	}
	return nil
}
