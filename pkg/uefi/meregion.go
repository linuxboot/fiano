// Copyright 2018 the LinuxBoot Authors. All rights reserved
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
// Table is expected to start with.
var (
	MEFTPSignature = []byte{0x24, 0x46, 0x50, 0x54}
)

const (
	// MEFTPSignatureLength represents the size of the ME FTP signature
	MEFTPSignatureLength = 4
	// MEPartitionTableEntryLength is the size of a partition table entry
	MEPartitionTableEntryLength = 32
)

// MEFPT is the main structure that represents an ME Flash Partition Table.
type MEFPT struct {
	// Holds the raw buffer
	buf []byte

	PartitionCount    uint32
	PartitionMapStart int
	Entries           []MePartitionEntry
	//Metadata for extraction and recovery
	ExtractPath string
}

// MePartitionEntry is an entry in FTP
type MePartitionEntry struct {
	Name     MeName
	Owner    [4]byte
	Offset   uint32
	Length   uint32
	Reserved [4]uint32
}

// MeName represent 4 bytes with JSON string support
// OK this is probably overkill!
type MeName [4]byte

// MarshalText converts MeName to a byte range (for JSON)
func (n MeName) MarshalText() ([]byte, error) {
	e := len(n)
	for e > 0 && n[e-1] == 0 {
		e--
	}
	return n[:e], nil
}

// UnmarshalText converts a byte range to MeName (for JSON)
func (n *MeName) UnmarshalText(b []byte) error {
	for i := range n[:] {
		var v byte
		if i < len(b) {
			v = b[i]
		}
		n[i] = v
	}
	return nil
}

func (n MeName) String() string {
	b, _ := n.MarshalText()
	return string(b)
}

// FindMESignature searches for an Intel ME FTP signature
func FindMESignature(buf []byte) (int, error) {
	if bytes.Equal(buf[16:16+MEFTPSignatureLength], MEFTPSignature) {
		// 16 + 4 since the descriptor starts after the signature
		return 20, nil
	}
	if bytes.Equal(buf[:MEFTPSignatureLength], MEFTPSignature) {
		// + 4 since the descriptor starts after the signature
		return MEFTPSignatureLength, nil
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
	o, err := FindMESignature(buf)
	if err != nil {
		return nil, err
	}
	if len(buf) < o+28 {
		return nil, fmt.Errorf("ME section (%#x) too small for ME Flash Partition Table (%#x)", len(buf), o+28)
	}
	fp := &MEFPT{PartitionMapStart: o + 28}
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
	r := bytes.NewReader(fp.buf[fp.PartitionMapStart:])
	for i := 0; i < int(fp.PartitionCount); i++ {
		var entry MePartitionEntry
		if err := binary.Read(r, binary.LittleEndian, &entry); err != nil {
			return err
		}
		fp.Entries = append(fp.Entries, entry)
	}
	return nil
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
	return nil
}
