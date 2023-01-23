// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/linuxboot/fiano/pkg/fsp"
)

const (
	// From https://github.com/IntelFsp/FSP/blob/master/ApolloLakeFspBinPkg/FspBin/Fsp.fd
	// under the FSP license. See README.md under `test_blobs`.
	FSPTestFile = "test_blobs/ApolloLakeFspBinPkg/Fsp.fd"
)

func TestNewInfoHeaderRealFile(t *testing.T) {
	buf, err := os.ReadFile(FSPTestFile)
	if err != nil {
		t.Errorf("Error opening test file %s: %v", FSPTestFile, err)
	}
	// in the ApolloLake FSP, the FSP header starts at byte 148. This can be
	// extracted by parsing it as uefi.FirmwareVolume, but it's not relevant for
	// this test, so let's go with raw offsets.
	hdr, err := fsp.NewInfoHeader(buf[148 : 148+fsp.HeaderV3Length])
	if err != nil {
		t.Errorf("NewInfoHeader failed to parse FSP file %s: %v", FSPTestFile, err)
	}
	if hdr.Signature != fsp.Signature {
		t.Errorf("Invalid signature %v; want %v", hdr.Signature, fsp.Signature)
	}
	if hdr.HeaderLength != fsp.HeaderV3Length {
		t.Errorf("Invalid header length %d; want %d", hdr.HeaderLength, fsp.HeaderV3Length)
	}
	if !bytes.Equal(hdr.Reserved1[:], bytes.Repeat([]byte{0}, 2)) {
		t.Errorf("Invalid field Reserved1 %v; want %v", hdr.Reserved1, bytes.Repeat([]byte{0}, 2))
	}
	if hdr.SpecVersion != fsp.SpecVersion(0x20) {
		t.Errorf("Invalid spec version %s; want %s", hdr.SpecVersion, fsp.SpecVersion(0x20))
	}
	if hdr.HeaderRevision != fsp.HeaderV3Revision {
		t.Errorf("Invalid header revision %d; want %d", hdr.HeaderRevision, fsp.HeaderV3Revision)
	}
	if hdr.ImageRevision != fsp.ImageRevision(0x01040301) {
		t.Errorf("Invalid image revision %s; want %s", hdr.ImageRevision, fsp.ImageRevision(0x1431))
	}
	if !bytes.Equal(hdr.ImageID[:], []byte("$APLFSP$")) {
		t.Errorf("Invalid image ID %s; want %s", hdr.ImageID, "$APLFSP$")
	}
	if hdr.ImageSize != 0x2a000 {
		t.Errorf("Invalid image size %#x; want %#x", hdr.ImageSize, 0x2a000)
	}
	if hdr.ImageBase != 0x200000 {
		t.Errorf("Invalid image base %#x; want %#x", hdr.ImageSize, 0x200000)
	}
	if hdr.ImageAttribute != 0x1 {
		t.Errorf("Invalid image attribute %#x; want %#x", hdr.ImageAttribute, 0x1)
	}
	if hdr.ComponentAttribute != 0x3003 {
		t.Errorf("Invalid component attribute %#x; want %#x", hdr.ComponentAttribute, 0x3003)
	}
	if hdr.CfgRegionOffset != 0x124 {
		t.Errorf("Invalid cfg region offset %#x; want %#x", hdr.CfgRegionOffset, 0x124)
	}
	if hdr.CfgRegionSize != 0x3b0 {
		t.Errorf("Invalid cfg region size %#x; want %#x", hdr.CfgRegionSize, 0x3b0)
	}
	if !bytes.Equal(hdr.Reserved2[:], bytes.Repeat([]byte{0}, 4)) {
		t.Errorf("Invalid field Reserved2 %v; want %v", hdr.Reserved2, bytes.Repeat([]byte{0}, 4))
	}
	if hdr.TempRAMInitEntryOffset != 0x0 {
		t.Errorf("Invalid temp RAM init entry offset %#x; want %#x", hdr.TempRAMInitEntryOffset, 0x0)
	}
	if !bytes.Equal(hdr.Reserved3[:], bytes.Repeat([]byte{0}, 4)) {
		t.Errorf("Invalid field Reserved3 %v; want %v", hdr.Reserved3, bytes.Repeat([]byte{0}, 4))
	}
	if hdr.NotifyPhaseEntryOffset != 0x580 {
		t.Errorf("Invalid notify phase entry offset %#x; want %#x", hdr.NotifyPhaseEntryOffset, 0x580)
	}
	if hdr.FSPMemoryInitEntryOffset != 0x0 {
		t.Errorf("Invalid FSP memory init entry offset %#x; want %#x", hdr.FSPMemoryInitEntryOffset, 0x0)
	}
	if hdr.TempRAMInitEntryOffset != 0x0 {
		t.Errorf("Invalid temp RAM init entry offset %#x; want %#x", hdr.TempRAMInitEntryOffset, 0x0)
	}
	if hdr.FSPSiliconInitEntryOffset != 0x58a {
		t.Errorf("Invalid FSP silicon init entry offset %#x; want %#x", hdr.FSPSiliconInitEntryOffset, 0x58a)
	}
}
