// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"testing"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/uefi"
)

type visitor struct {
	T *testing.T
}

func (v *visitor) Run(f uefi.Firmware) error {
	return f.Apply(v)
}
func (v *visitor) Visit(f uefi.Firmware) error {
	var guid *guid.GUID
	switch f := f.(type) {
	case *uefi.File:
		guid = &f.Header.GUID
	case *uefi.FirmwareVolume:
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

	updater := &positionUpdater{}
	if err := updater.Run(f); err != nil {
		t.Fatal(err)
	}

	visitor := &visitor{T: t}

	visitor.Run(f)

}
