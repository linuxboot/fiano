// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package fsp implements FSP info header parsing
package fsp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/linuxboot/fiano/pkg/log"
)

// TODO support FSP versions < 2.0
// TODO implement FSP_INFO_EXTENDED_HEADER

// FSP 2.0 specification
// https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/fsp-architecture-spec-v2.pdf

// values from the FSP 2.0 spec
var (
	Signature = [4]byte{'F', 'S', 'P', 'H'}
)

// constants from the FSP 2.0 spec
const (
	// size of the shared part of the header across FSP spec revisions
	FixedInfoHeaderLength = 12
	HeaderV3Length        = 72
	// FSP 2.0
	CurrentSpecVersion = SpecVersion(0x20)
	HeaderV3Revision   = 3
)

// FixedInfoHeader is the common header among the various revisions of the FSP
// info header.
type FixedInfoHeader struct {
	Signature      [4]byte
	HeaderLength   uint32
	Reserved1      [2]uint8
	SpecVersion    SpecVersion
	HeaderRevision uint8
}

// InfoHeaderRev3 represents the FSP_INFO_HEADER structure revision 3 (FSP
// 2.0) as defined by Intel.
type InfoHeaderRev3 struct {
	FixedInfoHeader
	ImageRevision             ImageRevision
	ImageID                   [8]byte
	ImageSize                 uint32
	ImageBase                 uint32
	ImageAttribute            ImageAttribute
	ComponentAttribute        ComponentAttribute
	CfgRegionOffset           uint32
	CfgRegionSize             uint32
	Reserved2                 [4]byte
	TempRAMInitEntryOffset    uint32
	Reserved3                 [4]byte
	NotifyPhaseEntryOffset    uint32
	FSPMemoryInitEntryOffset  uint32
	TempRAMExitEntryOffset    uint32
	FSPSiliconInitEntryOffset uint32
}

// CommonInfoHeader represents the FSP_INFO_HEADER structure
// revision independent
type CommonInfoHeader struct {
	Signature                      [4]byte
	HeaderLength                   uint32
	SpecVersion                    SpecVersion
	HeaderRevision                 uint8
	ImageRevision                  ImageRevision
	ImageID                        [8]byte
	ImageSize                      uint32
	ImageBase                      uint32
	ImageAttribute                 ImageAttribute
	ComponentAttribute             ComponentAttribute
	CfgRegionOffset                uint32
	CfgRegionSize                  uint32
	TempRAMInitEntryOffset         uint32
	NotifyPhaseEntryOffset         uint32
	FSPMemoryInitEntryOffset       uint32
	TempRAMExitEntryOffset         uint32
	FSPSiliconInitEntryOffset      uint32
	FspMultiPhaseSiInitEntryOffset uint32
	ExtendedImageRevision          uint16
}

// Summary prints a multi-line summary of the header's content.
func (ih CommonInfoHeader) Summary() string {
	s := fmt.Sprintf("Signature                   : %s\n", ih.Signature)
	s += fmt.Sprintf("Header Length               : %d\n", ih.HeaderLength)
	s += fmt.Sprintf("Spec Version                : %s\n", ih.SpecVersion)
	s += fmt.Sprintf("Header Revision             : %d\n", ih.HeaderRevision)
	s += fmt.Sprintf("Image Revision              : %s\n", ih.ImageRevision)
	s += fmt.Sprintf("Image ID                    : %s\n", ih.ImageID)
	s += fmt.Sprintf("Image Size                  : %#08x %d\n", ih.ImageSize, ih.ImageSize)
	s += fmt.Sprintf("Image Base                  : %#08x %d\n", ih.ImageBase, ih.ImageBase)
	s += fmt.Sprintf("Image Attribute             : %s\n", ih.ImageAttribute)
	s += fmt.Sprintf("Component Attribute         : %s\n", ih.ComponentAttribute)
	s += fmt.Sprintf("Cfg Region Offset           : %#08x %d\n", ih.CfgRegionOffset, ih.CfgRegionOffset)
	s += fmt.Sprintf("Cfg Region Size             : %#08x %d\n", ih.CfgRegionSize, ih.CfgRegionSize)
	s += fmt.Sprintf("TempRAMInit Entry Offset    : %#08x %d\n", ih.TempRAMInitEntryOffset, ih.TempRAMInitEntryOffset)
	s += fmt.Sprintf("NotifyPhase Entry Offset    : %#08x %d\n", ih.NotifyPhaseEntryOffset, ih.NotifyPhaseEntryOffset)
	s += fmt.Sprintf("FSPMemoryInit Entry Offset  : %#08x %d\n", ih.FSPMemoryInitEntryOffset, ih.FSPMemoryInitEntryOffset)
	s += fmt.Sprintf("TempRAMExit Entry Offset    : %#08x %d\n", ih.TempRAMExitEntryOffset, ih.TempRAMExitEntryOffset)
	s += fmt.Sprintf("FSPSiliconInit Entry Offset : %#08x %d\n", ih.FSPSiliconInitEntryOffset, ih.FSPSiliconInitEntryOffset)
	return s
}

// ImageRevision is the image revision field of the FSP info header.
type ImageRevision uint32

func (ir ImageRevision) String() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ir>>24)&0xff,
		(ir>>16)&0xff,
		(ir>>8)&0xff,
		ir&0xff,
	)
}

// SpecVersion represents the spec version as a packed BCD two-digit,
// dot-separated unsigned integer.
type SpecVersion uint8

func (sv SpecVersion) String() string {
	return fmt.Sprintf("%d.%d", (sv>>4)&0x0f, sv&0x0f)
}

// ImageAttribute represents the image attributes.
type ImageAttribute uint16

func (ia ImageAttribute) String() string {
	ret := fmt.Sprintf("%#04x ", uint16(ia))
	if ia.IsGraphicsDisplaySupported() {
		ret += "GraphicsDisplaySupported"
	} else {
		ret += "GraphicsDisplayNotSupported"
	}
	if uint16(ia) & ^(uint16(1)) != 0 {
		ret += " (reserved bits are not zeroed)"
	}
	return ret
}

// IsGraphicsDisplaySupported returns true if FSP supports enabling graphics display.
func (ia ImageAttribute) IsGraphicsDisplaySupported() bool {
	return uint16(ia)&0x1 == 1
}

// Type identifies the FSP type.
type Type uint8

// FSP types. All the other values are reserved.
var (
	TypeT Type = 1
	TypeM Type = 2
	TypeS Type = 3
	TypeO Type = 8
	// TypeReserved is a fake type that represents a reserved FSP type.
	TypeReserved Type
)

var fspTypeNames = map[Type]string{
	TypeT:        "FSP-T",
	TypeM:        "FSP-M",
	TypeS:        "FSP-S",
	TypeO:        "FSP-O",
	TypeReserved: "FSP-ReservedType",
}

// ComponentAttribute represents the component attribute.
type ComponentAttribute uint16

// IsDebugBuild returns true if the FSP build is a debug build, and false
// if it's a release build.
func (ca ComponentAttribute) IsDebugBuild() bool {
	return uint16(ca)&0x01 == 0
}

// IsTestRelease returns true if the release is a test release, and false if
// it's an official release.
func (ca ComponentAttribute) IsTestRelease() bool {
	return uint16(ca)&0x03 == 0
}

// Type returns the FSP type.
func (ca ComponentAttribute) Type() Type {
	typ := Type(uint16(ca) >> 12)
	if _, ok := fspTypeNames[typ]; ok {
		return typ
	}
	return TypeReserved
}

func (ca ComponentAttribute) String() string {
	var attrs []string
	if ca.IsDebugBuild() {
		attrs = append(attrs, "DebugBuild")
	} else {
		attrs = append(attrs, "ReleaseBuild")
	}
	if ca.IsTestRelease() {
		attrs = append(attrs, "TestRelease")
	} else {
		attrs = append(attrs, "OfficialRelease")
	}
	if typeName, ok := fspTypeNames[ca.Type()]; ok {
		attrs = append(attrs, typeName)
	} else {
		attrs = append(attrs, fmt.Sprintf("TypeUnknown(%v)", ca.Type()))
	}
	ret := fmt.Sprintf("%#04x %s", uint16(ca), strings.Join(attrs, "|"))
	// bits 11:2 are reserved
	if uint16(ca)&0x0ffe != 0 {
		ret += " (reserved bits are not zeroed)"
	}
	return ret
}

// NewInfoHeader creates an CommonInfoHeader from a byte buffer.
func NewInfoHeader(b []byte) (*CommonInfoHeader, error) {
	if len(b) < FixedInfoHeaderLength {
		return nil, fmt.Errorf("short FSP Info Header length %d; want at least %d", len(b), FixedInfoHeaderLength)
	}
	// TODO currently, only rev. 3 is supported
	var f InfoHeaderRev3

	reader := bytes.NewReader(b)
	if err := binary.Read(reader, binary.LittleEndian, &f.FixedInfoHeader); err != nil {
		return nil, err
	}

	// check signature
	if !bytes.Equal(f.Signature[:], Signature[:]) {
		return nil, fmt.Errorf("invalid signature %v; want %v", f.Signature, Signature)
	}
	// reserved bytes must be zero'ed
	if !bytes.Equal(f.Reserved1[:], []byte{0, 0}) {
		log.Warnf("reserved bytes must be zero, got %v", f.Reserved1)
	}
	// check spec version
	// TODO currently, only FSP 2.0 is supported
	if f.SpecVersion != CurrentSpecVersion {
		return nil, fmt.Errorf("cannot handle spec version %s; want %s", f.SpecVersion, CurrentSpecVersion)
	}
	// check header revision
	switch f.HeaderRevision {
	case HeaderV3Revision:
	default:
		return nil, fmt.Errorf("cannot handle header revision %d; want %d", f.HeaderRevision, HeaderV3Revision)
	}
	switch f.HeaderLength {
	case HeaderV3Length:
	default:
		return nil, fmt.Errorf("invalid header length %d; want %d", f.HeaderLength, HeaderV3Length)
	}

	// now that we know it's an info header spec 2.0, revision 3, re-read the
	// buffer to fill the whole header.
	reader = bytes.NewReader(b)
	if err := binary.Read(reader, binary.LittleEndian, &f); err != nil {
		return nil, err
	}

	// Fill common info header
	j, _ := json.Marshal(f)
	var c CommonInfoHeader
	if err := json.Unmarshal(j, &c); err != nil {
		return nil, err
	}
	return &c, nil

}
