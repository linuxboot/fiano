// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
)

// ME Partition parsing, the goal is to spot a padding in the ME Region
// after the ME partitions so that this region can be shrunk in the IFD.
//
// ME partition informations from http://me.bios.io/ME_blob_format

// MEFTPSignature is the sequence of bytes that an ME Flash Partition
// Table is expected to start with ie "$FPT".
var (
	MEFTPSignature = []byte{0x24, 0x46, 0x50, 0x54}
)

const (
	// MEPartitionDescriptorMinLength is the min size of the descriptor
	MEPartitionDescriptorMinLength = 28
	// MEPartitionTableEntryLength is the size of a partition table entry
	MEPartitionTableEntryLength = 32
)

// MEFPT is the main structure that represents an ME Flash Partition Table.
type MEFPT struct {
	// Holds the raw buffer
	buf []byte

	PartitionCount    uint32
	PartitionMapStart int
	Entries           []MEPartitionEntry
	// Metadata for extraction and recovery
	ExtractPath string
}

// MEPartitionEntry is an entry in FTP
type MEPartitionEntry struct {
	Name     MEName
	Owner    [4]byte
	Offset   uint32
	Length   uint32
	Reserved [4]uint32
}

// MEName represent 4 bytes with JSON string support
type MEName [4]byte

// MarshalText converts MEName to a byte range (for JSON)
func (n MEName) MarshalText() ([]byte, error) {
	return bytes.TrimRight(n[:], "\x00"), nil
}

// UnmarshalText converts a byte range to MEName (for JSON)
func (n *MEName) UnmarshalText(b []byte) error {
	var m MEName
	copy(m[:], b)
	*n = m
	if len(b) > len(m) {
		return fmt.Errorf("Can’t unmarshal %q to MEName, %d > %d", b, len(b), len(m))
	}
	return nil
}

func (n MEName) String() string {
	b, _ := n.MarshalText()
	return string(b)
}

// FindMEDescriptor searches for an Intel ME FTP signature
func FindMEDescriptor(buf []byte) (int, error) {
	if bytes.Equal(buf[16:16+len(MEFTPSignature)], MEFTPSignature) {
		// 16 + 4 since the descriptor starts after the signature
		return 16 + len(MEFTPSignature), nil
	}
	if bytes.Equal(buf[:len(MEFTPSignature)], MEFTPSignature) {
		// + 4 since the descriptor starts after the signature
		return len(MEFTPSignature), nil
	}
	return -1, fmt.Errorf("ME Flash Partition Table signature not found: first 20 bytes are:\n%s",
		hex.Dump(buf[:20]))
}

// Buf returns the buffer.
// Used mostly for things interacting with the Firmware interface.
func (fp *MEFPT) Buf() []byte {
	return fp.buf
}

// SetBuf sets the buffer.
// Used mostly for things interacting with the Firmware interface.
func (fp *MEFPT) SetBuf(buf []byte) {
	fp.buf = buf
}

// Apply calls the visitor on the MEFPT.
func (fp *MEFPT) Apply(v Visitor) error {
	return v.Visit(fp)
}

// ApplyChildren calls the visitor on each child node of MEFPT.
func (fp *MEFPT) ApplyChildren(v Visitor) error {
	return nil
}

// NewMEFPT tries to create a MEFPT
func NewMEFPT(buf []byte) (*MEFPT, error) {
	o, err := FindMEDescriptor(buf)
	if err != nil {
		return nil, err
	}
	if len(buf) < o+MEPartitionDescriptorMinLength {
		return nil, fmt.Errorf("ME section (%#x) too small for ME Flash Partition Table (%#x)", len(buf), o+MEPartitionDescriptorMinLength)
	}
	fp := &MEFPT{PartitionMapStart: o + MEPartitionDescriptorMinLength}
	r := bytes.NewReader(buf[o:])
	if err := binary.Read(r, binary.LittleEndian, &fp.PartitionCount); err != nil {
		return nil, err
	}
	l := fp.PartitionMapStart + MEPartitionTableEntryLength*int(fp.PartitionCount)
	if len(buf) < l {
		return nil, fmt.Errorf("ME section (%#x) too small for %d entries in ME Flash Partition Table (%#x)", len(buf), fp.PartitionCount, l)
	}

	fp.buf = make([]byte, l)
	copy(fp.buf, buf[:l])
	if err := fp.parsePartitions(); err != nil {
		return nil, err
	}
	return fp, nil
}

func (fp *MEFPT) parsePartitions() error {
	fp.Entries = make([]MEPartitionEntry, fp.PartitionCount)
	r := bytes.NewReader(fp.buf[fp.PartitionMapStart:])
	return binary.Read(r, binary.LittleEndian, fp.Entries)
}

// MERegion implements Region for a raw chunk of bytes in the firmware image.
type MERegion struct {
	FPT *MEFPT
	// holds the raw data
	buf []byte
	// Metadata for extraction and recovery
	ExtractPath string
	// This is a pointer to the FlashRegion struct laid out in the ifd.
	FRegion *FlashRegion
	// Region Type as per the IFD
	RegionType FlashRegionType
	// Computed free space after parsing the partition table
	FreeSpaceOffset uint64
}

// SetFlashRegion sets the flash region.
func (rr *MERegion) SetFlashRegion(fr *FlashRegion) {
	rr.FRegion = fr
}

// FlashRegion gets the flash region.
func (rr *MERegion) FlashRegion() (fr *FlashRegion) {
	return rr.FRegion
}

// NewMERegion creates a new region.
func NewMERegion(buf []byte, r *FlashRegion, rt FlashRegionType) (Region, error) {
	rr := &MERegion{FRegion: r, RegionType: rt}
	rr.buf = make([]byte, len(buf))
	copy(rr.buf, buf)
	fp, err := NewMEFPT(buf)
	if err != nil {
		log.Printf("error parsing ME Flash Partition Table: %v", err)
		return rr, nil
	}
	rr.FPT = fp
	// Compute FreeSpaceOffset
	for _, p := range fp.Entries {
		endOffset := uint64(p.Offset) + uint64(p.Length)
		if endOffset > rr.FreeSpaceOffset {
			rr.FreeSpaceOffset = endOffset
		}
	}

	return rr, nil
}

// Type returns the flash region type.
func (rr *MERegion) Type() FlashRegionType {
	return RegionTypeME
}

// Buf returns the buffer.
// Used mostly for things interacting with the Firmware interface.
func (rr *MERegion) Buf() []byte {
	return rr.buf
}

// SetBuf sets the buffer.
// Used mostly for things interacting with the Firmware interface.
func (rr *MERegion) SetBuf(buf []byte) {
	rr.buf = buf
}

// Apply calls the visitor on the MERegion.
func (rr *MERegion) Apply(v Visitor) error {
	return v.Visit(rr)
}

// ApplyChildren calls the visitor on each child node of MERegion.
func (rr *MERegion) ApplyChildren(v Visitor) error {
	if rr.FPT == nil {
		return nil
	}
	return rr.FPT.Apply(v)
}
