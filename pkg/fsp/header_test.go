// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fsp

import (
	"bytes"
	"testing"
)

var (
	FSPTestHeader = []byte("FSPHH\x00\x00\x00\x00\x00 \x03\x01\x03\x04\x01$APLFSP$\x00\xa0\x02\x00\x00\x00 \x00\x01\x00\x030$\x01\x00\x00\xb0\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8a\x05\x00\x00")
)

func TestNewInfoHeader(t *testing.T) {
	hdr, err := NewInfoHeader(FSPTestHeader)
	if err != nil {
		t.Errorf("NewInfoHeader failed to parse FSP header: %v", err)
	}
	if hdr.Signature != Signature {
		t.Errorf("Invalid signature %v; want %v", hdr.Signature, Signature)
	}
	if hdr.HeaderLength != HeaderV3Length {
		t.Errorf("Invalid header length %d; want %d", hdr.HeaderLength, HeaderV3Length)
	}
	if hdr.SpecVersion != SpecVersion(0x20) {
		t.Errorf("Invalid spec version %s; want %s", hdr.SpecVersion, SpecVersion(0x20))
	}
	if hdr.HeaderRevision != HeaderV3Revision {
		t.Errorf("Invalid header revision %d; want %d", hdr.HeaderRevision, HeaderV3Revision)
	}
	if hdr.ImageRevision != ImageRevision(0x01040301) {
		t.Errorf("Invalid image revision %s; want %s", hdr.ImageRevision, ImageRevision(0x1431))
	}
	if !bytes.Equal(hdr.ImageID[:], []byte("$APLFSP$")) {
		t.Errorf("Invalid image ID %s; want %s", hdr.ImageID, "$APLFSP$")
	}
	if hdr.ImageSize != 0x2a000 {
		t.Errorf("Invalid image size %#x; want %#x", hdr.ImageSize, 0x2a000)
	}
	if hdr.ImageBase != 0x200000 {
		t.Errorf("Invalid image base %#x; want %#x", hdr.ImageBase, 0x200000)
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
	if hdr.TempRAMInitEntryOffset != 0x0 {
		t.Errorf("Invalid temp RAM init entry offset %#x; want %#x", hdr.TempRAMInitEntryOffset, 0x0)
	}
	if hdr.NotifyPhaseEntryOffset != 0x580 {
		t.Errorf("Invalid notify phase entry offset %#x; want %#x", hdr.NotifyPhaseEntryOffset, 0x580)
	}
	if hdr.FSPMemoryInitEntryOffset != 0x0 {
		t.Errorf("Invalid FSP memory init entry offset %#x; want %#x", hdr.FSPMemoryInitEntryOffset, 0x0)
	}
	if hdr.TempRAMExitEntryOffset != 0x0 {
		t.Errorf("Invalid temp RAM exit entry offset %#x; want %#x", hdr.TempRAMExitEntryOffset, 0x0)
	}
	if hdr.FSPSiliconInitEntryOffset != 0x58a {
		t.Errorf("Invalid FSP silicon init entry offset %#x; want %#x", hdr.FSPSiliconInitEntryOffset, 0x58a)
	}
}

func TestComponentAttribute(t *testing.T) {
	ca := ComponentAttribute(0x3003)
	if ca.IsDebugBuild() {
		t.Errorf("Invalid component attribute: got debug build; want release build")
	}
	if ca.IsTestRelease() {
		t.Errorf("Invalid component attribute: got test release; want official release")
	}
	if ca.Type() != TypeS {
		t.Errorf("Invalid FSP type: got %v; want %v", ca.Type(), TypeS)
	}
	// test FSP type reserved
	ca = ComponentAttribute(0xffff)
	if ca.Type() != TypeReserved {
		t.Errorf("Invalid FSP type: got %v; want %v", ca.Type(), TypeReserved)
	}
}

func TestImageAttribute(t *testing.T) {
	// graphics display not supported
	ia := ImageAttribute(0)
	if ia.IsGraphicsDisplaySupported() {
		t.Errorf("Expected false, got true")
	}
	// graphics display supported
	ia = ImageAttribute(1)
	if !ia.IsGraphicsDisplaySupported() {
		t.Errorf("Expected true, got false")
	}
}

func TestNewInfoHeaderShortHeader(t *testing.T) {
	_, err := NewInfoHeader([]byte{})
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}

func TestNewInfoHeaderInvalidSignature(t *testing.T) {
	_, err := NewInfoHeader(bytes.Repeat([]byte{0xaa}, FixedInfoHeaderLength))
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}

func TestNewInfoHeaderNonZeroReserved1(t *testing.T) {
	_, err := NewInfoHeader(append(Signature[:], bytes.Repeat([]byte{0xaa}, FixedInfoHeaderLength)...))
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}
