// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fsp

import (
	"bytes"
	"testing"
)

var (
	FSPTestHeaderRev3 = []byte("FSPHH\x00\x00\x00\x00\x00 \x03\x01\x03\x04\x01$APLFSP$\x00\xa0\x02\x00\x00\x00 \x00\x01\x00\x030$\x01\x00\x00\xb0\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8a\x05\x00\x00")
	FSPTestHeaderRev4 = []byte("\x46\x53\x50\x48\x4c\x00\x00\x00\x00\x00\x21\x04\x3a\x00\x02\x02\x24\x43\x50\x58\x2d\x53\x50\x24\x00\x00\x04\x00\x00\x00\xcc\xff\x02\x00\x03\x30\x7c\x01\x00\x00\x58\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x98\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa2\x02\x00\x00\x00\x00\x00\x00")
	FSPTestHeaderRev5 = []byte("\x46\x53\x50\x48\x4c\x00\x00\x00\x00\x00\x22\x05\x71\x7d\x00\x0a\x54\x47\x4c\x49\x2d\x46\x53\x50\x00\xa0\x05\x00\x00\x00\xe3\xff\x03\x00\x03\x30\xb4\x06\x00\x00\xe0\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd8\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe2\x01\x00\x00\xec\x01\x00\x00")
	FSPTestHeaderRev6 = []byte("\x46\x53\x50\x48\x50\x00\x00\x00\x00\x00\x23\x06\x0f\x01\x01\x01\x24\x53\x50\x52\x2d\x53\x50\x24\x00\x80\x00\x00\x00\x00\xfe\xff\x02\x00\x00\x10\x4c\x02\x00\x00\x68\x00\x00\x00\x00\x00\x00\x00\x11\x24\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00")
)

func TestNewInfoHeaderRev3(t *testing.T) {
	hdr, err := NewInfoHeader(FSPTestHeaderRev3)
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
	if hdr.HeaderRevision != 3 {
		t.Errorf("Invalid header revision %d; want %d", hdr.HeaderRevision, 3)
	}
	if hdr.ImageRevision != ImageRevision(0x1000400030001) {
		t.Errorf("Invalid image revision %s; want %s", hdr.ImageRevision, ImageRevision(0x1000400030001))
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
	if hdr.FspMultiPhaseSiInitEntryOffset != 0 {
		t.Errorf("Invalid FSP silicon init entry offset %#x; want %#x", hdr.FspMultiPhaseSiInitEntryOffset, 0)
	}
}

func TestNewInfoHeaderRev4(t *testing.T) {
	hdr, err := NewInfoHeader(FSPTestHeaderRev4)
	if err != nil {
		t.Errorf("NewInfoHeader failed to parse FSP header: %v", err)
	}
	if hdr.Signature != Signature {
		t.Errorf("Invalid signature %v; want %v", hdr.Signature, Signature)
	}
	// This FSP violates the spec! Should be HeaderV4Length.
	if hdr.HeaderLength != HeaderV5Length {
		t.Errorf("Invalid header length %d; want %d", hdr.HeaderLength, HeaderV5Length)
	}
	if hdr.SpecVersion != SpecVersion(0x21) {
		t.Errorf("Invalid spec version %s; want %s", hdr.SpecVersion, SpecVersion(0x21))
	}
	if hdr.HeaderRevision != 4 {
		t.Errorf("Invalid header revision %d; want %d", hdr.HeaderRevision, 4)
	}
	if hdr.ImageRevision != ImageRevision(0x200020000003a) {
		t.Errorf("Invalid image revision %s; want %s", hdr.ImageRevision, ImageRevision(0x200020000003a))
	}
	if !bytes.Equal(hdr.ImageID[:], []byte("$CPX-SP$")) {
		t.Errorf("Invalid image ID %s; want %s", hdr.ImageID, "$CPX-SP$")
	}
	if hdr.ImageSize != 0x40000 {
		t.Errorf("Invalid image size %#x; want %#x", hdr.ImageSize, 0x40000)
	}
	if hdr.ImageBase != 0xffcc0000 {
		t.Errorf("Invalid image base %#x; want %#x", hdr.ImageBase, 0xffcc0000)
	}
	if hdr.ImageAttribute != 0x2 {
		t.Errorf("Invalid image attribute %#x; want %#x", int(hdr.ImageAttribute), 0x2)
	}
	if hdr.ComponentAttribute != 0x3003 {
		t.Errorf("Invalid component attribute %#x; want %#x", int(hdr.ComponentAttribute), 0x3003)
	}
	if hdr.CfgRegionOffset != 0x17c {
		t.Errorf("Invalid cfg region offset %#x; want %#x", hdr.CfgRegionOffset, 0x17c)
	}
	if hdr.CfgRegionSize != 0x58 {
		t.Errorf("Invalid cfg region size %#x; want %#x", hdr.CfgRegionSize, 0x58)
	}
	if hdr.TempRAMInitEntryOffset != 0x0 {
		t.Errorf("Invalid temp RAM init entry offset %#x; want %#x", hdr.TempRAMInitEntryOffset, 0x0)
	}
	if hdr.NotifyPhaseEntryOffset != 0x298 {
		t.Errorf("Invalid notify phase entry offset %#x; want %#x", hdr.NotifyPhaseEntryOffset, 0x298)
	}
	if hdr.FSPMemoryInitEntryOffset != 0x0 {
		t.Errorf("Invalid FSP memory init entry offset %#x; want %#x", hdr.FSPMemoryInitEntryOffset, 0x0)
	}
	if hdr.TempRAMExitEntryOffset != 0x0 {
		t.Errorf("Invalid temp RAM exit entry offset %#x; want %#x", hdr.TempRAMExitEntryOffset, 0x0)
	}
	if hdr.FSPSiliconInitEntryOffset != 0x2a2 {
		t.Errorf("Invalid FSP silicon init entry offset %#x; want %#x", hdr.FSPSiliconInitEntryOffset, 0x2a2)
	}
	if hdr.FspMultiPhaseSiInitEntryOffset != 0 {
		t.Errorf("Invalid FSP silicon init entry offset %#x; want %#x", hdr.FspMultiPhaseSiInitEntryOffset, 0)
	}
}

func TestNewInfoHeaderRev5(t *testing.T) {
	hdr, err := NewInfoHeader(FSPTestHeaderRev5)
	if err != nil {
		t.Errorf("NewInfoHeader failed to parse FSP header: %v", err)
	}
	if hdr.Signature != Signature {
		t.Errorf("Invalid signature %v; want %v", hdr.Signature, Signature)
	}
	if hdr.HeaderLength != HeaderV5Length {
		t.Errorf("Invalid header length %d; want %d", hdr.HeaderLength, HeaderV5Length)
	}
	if hdr.SpecVersion != SpecVersion(0x22) {
		t.Errorf("Invalid spec version %s; want %s", hdr.SpecVersion, SpecVersion(0x22))
	}
	if hdr.HeaderRevision != 5 {
		t.Errorf("Invalid header revision %d; want %d", hdr.HeaderRevision, 5)
	}
	if hdr.ImageRevision != ImageRevision(0xA0000007d0071) {
		t.Errorf("Invalid image revision %s; want %s", hdr.ImageRevision, ImageRevision(0xA0000007d0071))
	}
	if !bytes.Equal(hdr.ImageID[:], []byte("TGLI-FSP")) {
		t.Errorf("Invalid image ID %s; want %s", hdr.ImageID, "TGLI-FSP")
	}
	if hdr.ImageSize != 0x5a000 {
		t.Errorf("Invalid image size %#x; want %#x", hdr.ImageSize, 0x5a000)
	}
	if hdr.ImageBase != 0xffe30000 {
		t.Errorf("Invalid image base %#x; want %#x", hdr.ImageBase, 0xffe30000)
	}
	if hdr.ImageAttribute != 0x3 {
		t.Errorf("Invalid image attribute %#x; want %#x", int(hdr.ImageAttribute), 0x3)
	}
	if hdr.ComponentAttribute != 0x3003 {
		t.Errorf("Invalid component attribute %#x; want %#x", int(hdr.ComponentAttribute), 0x3003)
	}
	if hdr.CfgRegionOffset != 0x6b4 {
		t.Errorf("Invalid cfg region offset %#x; want %#x", hdr.CfgRegionOffset, 0x6b4)
	}
	if hdr.CfgRegionSize != 0xee0 {
		t.Errorf("Invalid cfg region size %#x; want %#x", hdr.CfgRegionSize, 0xee0)
	}
	if hdr.TempRAMInitEntryOffset != 0 {
		t.Errorf("Invalid temp RAM init entry offset %#x; want %#x", hdr.TempRAMInitEntryOffset, 0)
	}
	if hdr.NotifyPhaseEntryOffset != 0x1d8 {
		t.Errorf("Invalid notify phase entry offset %#x; want %#x", hdr.NotifyPhaseEntryOffset, 0x1d8)
	}
	if hdr.FSPMemoryInitEntryOffset != 0x0 {
		t.Errorf("Invalid FSP memory init entry offset %#x; want %#x", hdr.FSPMemoryInitEntryOffset, 0x0)
	}
	if hdr.TempRAMExitEntryOffset != 0x0 {
		t.Errorf("Invalid temp RAM exit entry offset %#x; want %#x", hdr.TempRAMExitEntryOffset, 0x0)
	}
	if hdr.FSPSiliconInitEntryOffset != 0x1e2 {
		t.Errorf("Invalid silicon init entry offset %#x; want %#x", hdr.FSPSiliconInitEntryOffset, 0x1e2)
	}
	if hdr.FspMultiPhaseSiInitEntryOffset != 0x1ec {
		t.Errorf("Invalid Multi Phase Si entry offset %#x; want %#x", hdr.FspMultiPhaseSiInitEntryOffset, 0x1ec)
	}
}

func TestNewInfoHeaderRev6(t *testing.T) {
	hdr, err := NewInfoHeader(FSPTestHeaderRev6)
	if err != nil {
		t.Errorf("NewInfoHeader failed to parse FSP header: %v", err)
	}
	if hdr.Signature != Signature {
		t.Errorf("Invalid signature %v; want %v", hdr.Signature, Signature)
	}
	if hdr.HeaderLength != HeaderV6Length {
		t.Errorf("Invalid header length %d; want %d", hdr.HeaderLength, HeaderV6Length)
	}
	if hdr.SpecVersion != SpecVersion(0x23) {
		t.Errorf("Invalid spec version %s; want %s", hdr.SpecVersion, SpecVersion(0x23))
	}
	if hdr.HeaderRevision != 6 {
		t.Errorf("Invalid header revision %d; want %d", hdr.HeaderRevision, 6)
	}
	if hdr.ImageRevision != ImageRevision(0x100010001020F) {
		t.Errorf("Invalid image revision %s; want %s", hdr.ImageRevision, ImageRevision(0x100010001020F))
	}
	if !bytes.Equal(hdr.ImageID[:], []byte("$SPR-SP$")) {
		t.Errorf("Invalid image ID %s; want %s", hdr.ImageID, "$SPR-SP$")
	}
	if hdr.ImageSize != 0x8000 {
		t.Errorf("Invalid image size %#x; want %#x", hdr.ImageSize, 0x8000)
	}
	if hdr.ImageBase != 0xfffe0000 {
		t.Errorf("Invalid image base %#x; want %#x", hdr.ImageBase, 0xfffe0000)
	}
	if hdr.ImageAttribute != 0x2 {
		t.Errorf("Invalid image attribute %#x; want %#x", int(hdr.ImageAttribute), 0x2)
	}
	if hdr.ComponentAttribute != 0x1000 {
		t.Errorf("Invalid component attribute %#x; want %#x", int(hdr.ComponentAttribute), 0x1000)
	}
	if hdr.CfgRegionOffset != 0x24c {
		t.Errorf("Invalid cfg region offset %#x; want %#x", hdr.CfgRegionOffset, 0x24c)
	}
	if hdr.CfgRegionSize != 0x68 {
		t.Errorf("Invalid cfg region size %#x; want %#x", hdr.CfgRegionSize, 0x68)
	}
	if hdr.TempRAMInitEntryOffset != 0x2411 {
		t.Errorf("Invalid temp RAM init entry offset %#x; want %#x", hdr.TempRAMInitEntryOffset, 0x2411)
	}
	if hdr.NotifyPhaseEntryOffset != 0 {
		t.Errorf("Invalid notify phase entry offset %#x; want %#x", hdr.NotifyPhaseEntryOffset, 0)
	}
	if hdr.FSPMemoryInitEntryOffset != 0x0 {
		t.Errorf("Invalid FSP memory init entry offset %#x; want %#x", hdr.FSPMemoryInitEntryOffset, 0x0)
	}
	if hdr.TempRAMExitEntryOffset != 0x0 {
		t.Errorf("Invalid temp RAM exit entry offset %#x; want %#x", hdr.TempRAMExitEntryOffset, 0x0)
	}
	if hdr.FSPSiliconInitEntryOffset != 0x0 {
		t.Errorf("Invalid silicon init entry offset %#x; want %#x", hdr.FSPSiliconInitEntryOffset, 0x0)
	}
	if hdr.FspMultiPhaseSiInitEntryOffset != 0 {
		t.Errorf("Invalid Multi Phase Si entry offset %#x; want %#x", hdr.FspMultiPhaseSiInitEntryOffset, 0)
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
	// graphics display not supported, dispatch mode not supported
	ia := ImageAttribute(0)
	if ia.IsGraphicsDisplaySupported() {
		t.Errorf("Expected false, got true")
	}
	// graphics display supported
	ia = ImageAttribute(1)
	if !ia.IsGraphicsDisplaySupported() {
		t.Errorf("Expected true, got false")
	}
	// dispatch mode supported
	ia = ImageAttribute(2)
	if !ia.IsDispatchModeSupported() {
		t.Errorf("Expected true, got false")
	}
	if ia.IsGraphicsDisplaySupported() {
		t.Errorf("Expected false, got true")
	}
	// graphics display supported, dispatch mode supported
	ia = ImageAttribute(3)
	if !ia.IsDispatchModeSupported() || !ia.IsGraphicsDisplaySupported() {
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
