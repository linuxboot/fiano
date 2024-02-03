// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

import (
	"io/ioutil"
	"testing"

	"github.com/linuxboot/fiano/pkg/guid"
)

type visitor struct {
	T *testing.T
}

func parseImage(t *testing.T) Firmware {
	image, err := ioutil.ReadFile("../../integration/roms/OVMF.rom")
	if err != nil {
		t.Fatal(err)
	}
	parsedRoot, err := Parse(image)
	if err != nil {
		t.Fatal(err)
	}
	return parsedRoot
}

func (v *visitor) Run(f Firmware) error {
	return f.Apply(v)
}
func (v *visitor) Visit(f Firmware) error {
	var guid *guid.GUID
	switch f := f.(type) {
	case *File:
		guid = &f.Header.GUID
	case *FirmwareVolume:
		guid = &f.FVName
	default:
		return f.ApplyChildren(v)
	}

	expectedPosition, ok := map[string]uint64{
		"00000000-0000-0000-0000-000000000000": 0x0,
		"48DB5E17-707C-472D-91CD-1613E7EF51B0": 0x84000,
		"763BED0D-DE9F-48F5-81F1-3E90E1B1A015": 0x3CC000,
	}[guid.String()]

	if ok && f.Position() != expectedPosition {
		v.T.Fatalf("expected value at %s would be %X but instead was %X", guid.String(), expectedPosition, f.Position())
	}

	return f.ApplyChildren(v)
}

func TestUpdatePositions(t *testing.T) {

	f := parseImage(t)

	updater := &PositionUpdater{}
	if err := updater.Run(f); err != nil {
		t.Fatal(err)
	}

	visitor := &visitor{T: t}

	visitor.Run(f)

}
