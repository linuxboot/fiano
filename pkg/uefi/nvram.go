// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// NVAR decoding logic ported from UEFITool Copyright (c) 2016, Nikolaj Schlej.
// https://github.com/LongSoft/UEFITool/blob/new_engine/common/nvramparser.cpp
// The author described his reverse engineering work on his blog:
// https://habr.com/en/post/281901/

package uefi

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/unicode"
)

// NVarAttribute represent Attributes
type NVarAttribute uint8

// Attributes
const (
	NVarEntryRuntime       NVarAttribute = 0x01
	NVarEntryASCIIName     NVarAttribute = 0x02
	NVarEntryGUID          NVarAttribute = 0x04
	NVarEntryDataOnly      NVarAttribute = 0x08
	NVarEntryExtHeader     NVarAttribute = 0x10
	NVarEntryHWErrorRecord NVarAttribute = 0x20
	NVarEntryAuthWrite     NVarAttribute = 0x40
	NVarEntryValid         NVarAttribute = 0x80
)

// IsValid returns the Valid attribute as boolean
func (a NVarAttribute) IsValid() bool {
	return a&NVarEntryValid != 0
}

// NVarEntrySignature value for 'NVAR' signature
const NVarEntrySignature uint32 = 0x5241564E

// NVarHeader represents an NVAR entry header
type NVarHeader struct {
	Signature  uint32 `json:"-"`
	Size       uint16
	Next       [3]uint8 `json:"-"`
	Attributes NVarAttribute
}

// NVarEntryType represent the computed type of an NVAR entry
type NVarEntryType uint8

// Types
const (
	InvalidNVarEntry NVarEntryType = iota
	InvalidLinkNVarEntry
	LinkNVarEntry
	DataNVarEntry
	FullNVarEntry
)

var nVarEntryTypeName = map[NVarEntryType]string{
	InvalidNVarEntry:     "Invalid",
	InvalidLinkNVarEntry: "Invalid link",
	LinkNVarEntry:        "Link",
	DataNVarEntry:        "Data",
	FullNVarEntry:        "Full",
}

func (t NVarEntryType) String() string {
	if s, ok := nVarEntryTypeName[t]; ok {
		return s
	}
	return "UNKNOWN"
}

// NVarExtAttribute represent extended attributes
type NVarExtAttribute uint8

// Extended attributes values
const (
	NVarEntryExtChecksum    NVarExtAttribute = 0x01
	NVarEntryExtAuthWrite   NVarExtAttribute = 0x10
	NVarEntryExtTimeBased   NVarExtAttribute = 0x20
	NVarEntryExtUnknownMask NVarExtAttribute = 0xCE
)

// NVar represent an NVAR entry
type NVar struct {
	Header    NVarHeader
	GUID      guid.GUID
	GUIDIndex *uint8 `json:",omitempty"`
	Name      string

	NVarStore *NVarStore `json:",omitempty"`

	//Decoded data
	Type       NVarEntryType
	Offset     uint64
	NextOffset uint64

	//Extended Header
	ExtAttributes               *NVarExtAttribute `json:",omitempty"`
	Checksum                    *uint8            `json:",omitempty"`
	ExpectedChecksum            *uint8            `json:",omitempty"`
	TimeStamp                   *uint64           `json:",omitempty"`
	Hash                        []byte            `json:",omitempty"`
	UnknownExtendedHeaderFormat bool              `json:",omitempty"`

	//Metadata for extraction and recovery
	buf         []byte
	ExtractPath string
	DataOffset  int64
	ExtOffset   int64 `json:",omitempty"`
}

// String returns the String value of the NVAR: Type and Name if valid
func (v *NVar) String() string {
	if v.IsValid() {
		return fmt.Sprintf("[%s] %v", v.Type, v.Name)
	}
	return fmt.Sprintf("[%s]", v.Type)
}

// Buf returns the buffer.
// Used mostly for things interacting with the Firmware interface.
func (v *NVar) Buf() []byte {
	return v.buf
}

// SetBuf sets the buffer.
// Used mostly for things interacting with the Firmware interface.
func (v *NVar) SetBuf(buf []byte) {
	v.buf = buf
}

// Apply calls the visitor on the NVar.
func (v *NVar) Apply(vr Visitor) error {
	return vr.Visit(v)
}

// ApplyChildren calls the visitor on each child node of NVar.
func (v *NVar) ApplyChildren(vr Visitor) error {
	if v.NVarStore != nil {
		if err := v.NVarStore.Apply(vr); err != nil {
			return err
		}
	}
	return nil
}

// NVarStore represent an NVAR store
type NVarStore struct {
	Entries   []*NVar
	GUIDStore []guid.GUID `json:",omitempty"`

	//Metadata for extraction and recovery
	buf             []byte
	FreeSpaceOffset uint64
	GUIDStoreOffset uint64
	Length          uint64
}

// Buf returns the buffer.
// Used mostly for things interacting with the Firmware interface.
func (s *NVarStore) Buf() []byte {
	return s.buf
}

// SetBuf sets the buffer.
// Used mostly for things interacting with the Firmware interface.
func (s *NVarStore) SetBuf(buf []byte) {
	s.buf = buf
}

// Apply calls the visitor on the NVarStore.
func (s *NVarStore) Apply(v Visitor) error {
	return v.Visit(s)
}

// ApplyChildren calls the visitor on each child node of NVarStore.
func (s *NVarStore) ApplyChildren(v Visitor) error {
	for _, nv := range s.Entries {
		if err := nv.Apply(v); err != nil {
			return err
		}
	}
	return nil
}

func (s *NVarStore) getGUIDFromStore(i uint8) guid.GUID {
	var GUID guid.GUID
	if len(s.GUIDStore) < int(i+1) {
		// Read GUID in reverse order from the buffer
		r := bytes.NewReader(s.buf)
		if _, err := r.Seek(-int64(binary.Size(GUID))*int64(i+1), io.SeekEnd); err != nil {
			// not returning an error as this is really unlikely, in most
			// overflow case we will read NVAR content as GUID as the store
			// buffer is expected to be big enough...
			return *ZeroGUID
		}
		a := make([]guid.GUID, int(i+1)-len(s.GUIDStore))
		for j := int(i) - len(s.GUIDStore); j >= 0; j-- {
			// no error check as the Seek will fail first
			binary.Read(r, binary.LittleEndian, &a[j])
		}
		s.GUIDStore = append(s.GUIDStore, a...)
	}
	return s.GUIDStore[i]
}

func (v *NVar) parseHeader(buf []byte) error {
	// Read in standard header.
	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &v.Header); err != nil {
		return err
	}
	if v.Header.Signature != NVarEntrySignature {
		return fmt.Errorf("NVAR Signature not found")
	}
	if len(buf) < int(v.Header.Size) {
		return fmt.Errorf("NVAR Size bigger than remaining size")
	}
	v.DataOffset = int64(binary.Size(v.Header))
	return nil
}

// IsValid tells whether an entry is valid
func (v *NVar) IsValid() bool {
	switch v.Type {
	case LinkNVarEntry, DataNVarEntry, FullNVarEntry:
		return true
	default:
		return false
	}
}

func (v *NVar) parseNext() error {
	var lastVariableFlag uint64
	if Attributes.ErasePolarity == 0xFF {
		lastVariableFlag = 0xFFFFFF
	} else if Attributes.ErasePolarity == 0 {
		lastVariableFlag = 0
	} else {
		return fmt.Errorf("erase polarity not 0x00 or 0xFF, got %#x", Attributes.ErasePolarity)
	}

	// Add next node information
	next := Read3Size(v.Header.Next)
	if next != lastVariableFlag {
		v.Type = LinkNVarEntry
		v.NextOffset = v.Offset + next
	}
	return nil
}

func (v *NVar) parseExtendedHeader() error {
	var knownExtDataFormat bool
	if v.Header.Attributes&NVarEntryExtHeader == 0 {
		return nil
	}
	var extendedHeaderSize uint16
	r := bytes.NewReader(v.buf)
	if _, err := r.Seek(-int64(binary.Size(extendedHeaderSize)), io.SeekEnd); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &extendedHeaderSize); err != nil {
		return err
	}
	// Sanity check extendedHeaderSize < body size
	bodySize := int64(v.Header.Size) - v.DataOffset
	if int64(extendedHeaderSize) > bodySize {
		return fmt.Errorf("extended header size (%#x) is greater than body size (%#x)", extendedHeaderSize, bodySize)
	}
	v.ExtOffset = int64(v.Header.Size) - int64(extendedHeaderSize)
	if _, err := r.Seek(v.ExtOffset, io.SeekStart); err != nil {
		return err
	}
	var extAttributes NVarExtAttribute
	if err := binary.Read(r, binary.LittleEndian, &extAttributes); err != nil {
		return err
	}
	v.ExtAttributes = &extAttributes
	// Variable with checksum
	if extAttributes&NVarEntryExtChecksum != 0 {
		// Get stored checksum
		var storedChecksum uint8
		storedChecksum = v.buf[int64(v.Header.Size)-int64(binary.Size(extendedHeaderSize)+binary.Size(storedChecksum))]
		v.Checksum = &storedChecksum
		// Recalculate checksum for the variable
		calculatedChecksum := uint8(0)
		// [0-3] _Skip_  entry 'NVAR' signature
		// [4-5] Include entry size and flags
		// [6-8] _Skip_  entry next (So linking will not invalidate the sum)
		// [ 9 ] Include entry attributes
		// [10-] Include entry data
		for i := int64(4); i < int64(v.Header.Size); i++ {
			calculatedChecksum += v.buf[i]
			if i == 5 {
				i += 3 // Skip Next
			}
		}
		if calculatedChecksum != 0 {
			calculatedChecksum = -calculatedChecksum
			v.ExpectedChecksum = &calculatedChecksum
		}
		knownExtDataFormat = true
	}

	if v.Header.Attributes&NVarEntryAuthWrite == 0 {
		var timestamp uint64
		if err := binary.Read(r, binary.LittleEndian, &timestamp); err != nil {
			switch err {
			case io.EOF, io.ErrUnexpectedEOF:
				return fmt.Errorf("extended header size (%#x) is too small for timestamp", extendedHeaderSize)
			default:
				return err
			}
		}
		if v.Header.Attributes&NVarEntryDataOnly != 0 {
			// Full or link variable have hash
			hashstart, err := r.Seek(0, io.SeekCurrent)
			if err != nil {
				return err
			}
			if hashstart+sha256.Size > int64(v.Header.Size) {
				return fmt.Errorf("extended header size (%#x) is too small for hash", extendedHeaderSize)
			}
			v.Hash = make([]byte, sha256.Size)
			copy(v.Hash, v.buf[hashstart:hashstart+sha256.Size])
		}
		knownExtDataFormat = true
	}
	v.UnknownExtendedHeaderFormat = !knownExtDataFormat
	return nil
}

func (v *NVar) parseDataOnly(s *NVarStore) bool {
	if v.Header.Attributes&NVarEntryDataOnly == 0 {
		return false
	}
	// Search previously added entries for a link to this variable
	// Note: We expect links to be from previous to new entries as links
	// are used to replace the values while keeping the Name and GUID.
	// TODO: fix if we ever met legitimate rom that defeat this assumption.
	var link *NVar
	for _, l := range s.Entries {
		if l.IsValid() && l.NextOffset == v.Offset {
			link = l
			break
		}
	}
	if link != nil {
		v.GUID = link.GUID
		v.Name = link.Name
		if v.NextOffset == 0 {
			v.Type = DataNVarEntry
		}
	} else {
		v.Name = "Invalid link"
		v.Type = InvalidLinkNVarEntry
	}

	return true
}

func (v *NVar) parseGUID(s *NVarStore) error {
	r := bytes.NewReader(v.buf[v.DataOffset:])
	if v.Header.Attributes&NVarEntryGUID != 0 {
		// GUID in variable
		if err := binary.Read(r, binary.LittleEndian, &v.GUID); err != nil {
			return err
		}
		v.DataOffset += int64(binary.Size(v.GUID))
	} else {
		// GUID index in store
		var guidIndex uint8
		if err := binary.Read(r, binary.LittleEndian, &guidIndex); err != nil {
			return err
		}
		v.GUIDIndex = &guidIndex
		v.GUID = s.getGUIDFromStore(guidIndex)
		v.DataOffset += int64(binary.Size(guidIndex))
	}
	return nil
}

func (v *NVar) parseName() error {
	if v.Header.Attributes&NVarEntryASCIIName != 0 {
		// Name is stored as ASCII string of CHAR8s
		namebuf := v.buf[v.DataOffset:]
		end := bytes.IndexByte(namebuf, 0)
		if end == -1 {
			return io.EOF
		}
		v.Name = string(namebuf[:end])
		v.DataOffset += int64(end) + 1
	} else {
		// Name is stored as UCS2 string of CHAR16s
		namebuf := v.buf[v.DataOffset:]
		end := bytes.Index(namebuf, []byte{0, 0})
		if end == -1 {
			return io.EOF
		}
		v.Name = unicode.UCS2ToUTF8(namebuf[:end])
		v.DataOffset += int64(end) + 2
	}
	return nil
}

func (v *NVar) parseContent(buf []byte) error {
	// Try parsing as NVAR storage if it begins with NVAR signature
	r := bytes.NewReader(buf)
	var signature uint32
	if err := binary.Read(r, binary.LittleEndian, &signature); err != nil {
		return err
	}
	if signature != NVarEntrySignature {
		return fmt.Errorf("NVAR Signature not found")
	}
	ns, err := NewNVarStore(buf)
	if err != nil {
		return fmt.Errorf("error parsing NVAR store in var %v: %v", v.Name, err)
	}
	v.NVarStore = ns
	return nil
}

// newNVar parses a sequence of bytes and returns an NVar
// object, if a valid one is passed, returns nil if buf is clear, or an error.
func newNVar(buf []byte, offset uint64, s *NVarStore) (*NVar, error) {
	// Check if remaining space is erased
	if IsErased(buf, Attributes.ErasePolarity) {
		return nil, nil
	}

	v := NVar{Type: FullNVarEntry, Offset: offset}
	// read the header and check for existing NVAR
	if err := v.parseHeader(buf); err != nil {
		return nil, err
	}

	// Copy out the buffer.
	newBuf := buf[:v.Header.Size]
	v.buf = make([]byte, v.Header.Size)
	copy(v.buf, newBuf)

	// Entry is marked as invalid
	if !v.Header.Attributes.IsValid() {
		v.Name = "Invalid"
		v.Type = InvalidNVarEntry
		return &v, nil
	}

	// Parse next node information
	if err := v.parseNext(); err != nil {
		return nil, err
	}

	// Entry with extended header
	if err := v.parseExtendedHeader(); err != nil {
		v.Name = fmt.Sprintf("Invalid ExtHeader, %v", err)
		v.Type = InvalidNVarEntry
		return &v, nil
	}

	// Entry is data-only (nameless and GUIDless entry or link)
	if !v.parseDataOnly(s) {
		// Get entry name and GUID
		if err := v.parseGUID(s); err != nil {
			return nil, err
		}
		if err := v.parseName(); err != nil {
			return nil, err
		}
	}

	// Try parsing the entry content
	_ = v.parseContent(v.buf[v.DataOffset:])

	return &v, nil
}

// Assemble takes in the content and assembles the NVAR binary
// Warning: when checkOnly is false the resulting NVar must be Assembled again
// to fix the header content
func (v *NVar) Assemble(content []byte, checkOnly bool) error {
	if !v.IsValid() {
		return errors.New("unable to construct Invalid NVAR")
	}
	vData := new(bytes.Buffer)
	v.Header.Signature = NVarEntrySignature
	if v.NextOffset != 0 && !checkOnly {
		return errors.New("unable to update data in link, use compact first")
	}
	if v.NextOffset != 0 {
		v.Header.Next = Write3Size(v.NextOffset - v.Offset)
	} else {
		v.Header.Next = [3]uint8{Attributes.ErasePolarity, Attributes.ErasePolarity, Attributes.ErasePolarity}
	}
	err := binary.Write(vData, binary.LittleEndian, v.Header)
	if err != nil {
		return fmt.Errorf("unable to construct binary header of NVAR: got %v", err)
	}
	// GUID
	if v.Header.Attributes&NVarEntryDataOnly == 0 {
		if v.Header.Attributes&NVarEntryGUID != 0 {
			err := binary.Write(vData, binary.LittleEndian, v.GUID)
			if err != nil {
				return fmt.Errorf("unable to add GUID to NVAR: got %v", err)
			}
		} else {
			err := binary.Write(vData, binary.LittleEndian, *v.GUIDIndex)
			if err != nil {
				return fmt.Errorf("unable to add GUID index to NVAR: got %v", err)
			}
		}
		// Name
		if v.Header.Attributes&NVarEntryASCIIName != 0 {
			_, err := vData.Write([]byte(v.Name))
			if err != nil {
				return fmt.Errorf("unable to add Name to NVAR: got %v", err)
			}
			err = vData.WriteByte(0)
			if err != nil {
				return fmt.Errorf("unable to add Name to NVAR: got %v", err)
			}
		} else {
			_, err := vData.Write(unicode.UTF8ToUCS2(v.Name))
			if err != nil {
				return fmt.Errorf("unable to add Name to NVAR: got %v", err)
			}
		}
	}
	//check/update DataOffset
	if checkOnly {
		if v.DataOffset != int64(vData.Len()) {
			return fmt.Errorf("NVAR header size mismatch, expected %v got %v", v.DataOffset, vData.Len())
		}
	} else {
		v.DataOffset = int64(vData.Len())
	}
	_, err = vData.Write(content)
	if err != nil {
		return fmt.Errorf("unable to add content to NVAR: got %v", err)
	}
	//check/update Header.Size
	if checkOnly {
		if v.Header.Size != uint16(vData.Len()) {
			return fmt.Errorf("NVAR size mismatch, expected %v got %v", v.Header.Size, vData.Len())
		}
	} else {
		v.Header.Size = uint16(vData.Len())
	}
	v.SetBuf(vData.Bytes())
	return nil
}

// NewNVarStore parses a sequence of bytes and returns an NVarStore
// object, if a valid one is passed, or an error.
func NewNVarStore(buf []byte) (*NVarStore, error) {
	s := NVarStore{}

	// Copy out the buffer.
	s.buf = make([]byte, len(buf))
	copy(s.buf, buf)

	s.Length = uint64(len(buf))
	s.GUIDStoreOffset = s.Length

	for s.FreeSpaceOffset = uint64(0); s.FreeSpaceOffset < s.GUIDStoreOffset; {
		v, err := newNVar(s.buf[s.FreeSpaceOffset:s.GUIDStoreOffset], s.FreeSpaceOffset, &s)
		if err != nil {
			return nil, fmt.Errorf("error parsing NVAR entry at offset %#x: %v", s.FreeSpaceOffset, err)
		}
		if v == nil {
			break
		}
		s.Entries = append(s.Entries, v)
		s.FreeSpaceOffset += uint64(v.Header.Size)
		s.GUIDStoreOffset = s.Length - uint64(binary.Size(guid.GUID{}))*uint64(len(s.GUIDStore))
	}

	return &s, nil
}

// GetGUIDStoreBuf returns the binary representation of the GUIDStore
func (s *NVarStore) GetGUIDStoreBuf() ([]byte, error) {
	guidStoreWBuf := new(bytes.Buffer)
	for i := len(s.GUIDStore) - 1; i >= 0; i-- {
		err := binary.Write(guidStoreWBuf, binary.LittleEndian, s.GUIDStore[i])
		if err != nil {
			return nil, fmt.Errorf("unable to write GUID index to store: got %v", err)
		}
	}
	return guidStoreWBuf.Bytes(), nil
}
