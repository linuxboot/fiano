// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package fmap parses flash maps.
package fmap

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"
)

// Signature of the fmap structure.
var Signature = []byte("__FMAP__")

// Flags which can be applied to Area.Flags.
const (
	FmapAreaStatic = 1 << iota
	FmapAreaCompressed
	FmapAreaReadOnly
)

// String wraps around byte array to give us more control over how strings are
// serialized.
type String struct {
	Value [32]uint8
}

func (s *String) String() string {
	return strings.TrimRight(string(s.Value[:]), "\x00")
}

// MarshalJSON implements json.Marshaler.
func (s *String) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *String) UnmarshalJSON(b []byte) error {
	str, err := strconv.Unquote(string(b))
	if err != nil {
		return err
	}
	if len(str) > len(s.Value) {
		return fmt.Errorf("String %#v is longer than 32 bytes", str)
	}
	copy(s.Value[:], []byte(str))
	return nil
}

// FMap structure serializable using encoding.Binary.
type FMap struct {
	Header
	Areas []Area
}

// Header describes the flash part.
type Header struct {
	Signature [8]uint8
	VerMajor  uint8
	VerMinor  uint8
	Base      uint64
	Size      uint32
	Name      String
	NAreas    uint16
}

// Area describes each area.
type Area struct {
	Offset uint32
	Size   uint32
	Name   String
	Flags  uint16
}

// Metadata contains additional data not part of the FMap.
type Metadata struct {
	Start uint64
}

func headerValid(h *Header) bool {
	if h.VerMajor != 1 {
		return false
	}
	// Check if some sensible value is used for the full flash size
	if h.Size == 0 {
		return false
	}

	// Name is specified to be null terminated single-word string without spaces
	return bytes.Contains(h.Name.Value[:], []byte("\x00"))
}

// FlagNames returns human readable representation of the flags.
func FlagNames(flags uint16) string {
	names := []string{}
	m := []struct {
		val  uint16
		name string
	}{
		{FmapAreaStatic, "STATIC"},
		{FmapAreaCompressed, "COMPRESSED"},
		{FmapAreaReadOnly, "READ_ONLY"},
	}
	for _, v := range m {
		if v.val&flags != 0 {
			names = append(names, v.name)
			flags -= v.val
		}
	}
	// Write a hex value for unknown flags.
	if flags != 0 || len(names) == 0 {
		names = append(names, fmt.Sprintf("%#x", flags))
	}
	return strings.Join(names, "|")
}

var errEOF = errors.New("unexpected EOF while parsing fmap")

func readField(r io.Reader, data interface{}) error {
	// The endianness might depend on your machine or it might not.
	if err := binary.Read(r, binary.LittleEndian, data); err != nil {
		return errEOF
	}
	return nil
}

var errSigNotFound = errors.New("cannot find FMAP signature")
var errMultipleFound = errors.New("found multiple fmap")

// Read an FMap into the data structure.
func Read(f io.Reader) (*FMap, *Metadata, error) {
	// Read flash into memory.
	// TODO: it is possible to parse fmap without reading entire file into memory
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}

	// Loop over __FMAP__ occurrences until a valid header is found
	start := 0
	validFmaps := 0
	var fmap FMap
	var fmapMetadata Metadata
	for {
		if start >= len(data) {
			break
		}

		next := bytes.Index(data[start:], Signature)
		if next == -1 {
			break
		}
		start += next

		// Reader anchored to the start of the fmap
		r := bytes.NewReader(data[start:])

		// Read fields.
		var testFmap FMap
		if err := readField(r, &testFmap.Header); err != nil {
			return nil, nil, err
		}
		if !headerValid(&testFmap.Header) {
			start += len(Signature)
			continue
		}
		fmap = testFmap
		validFmaps++

		fmap.Areas = make([]Area, fmap.NAreas)
		err := readField(r, &fmap.Areas)
		if err != nil {
			return nil, nil, err
		}
		// Return useful metadata
		fmapMetadata = Metadata{
			Start: uint64(start),
		}
		start += len(Signature)
	}
	if validFmaps >= 2 {
		return nil, nil, errMultipleFound
	} else if validFmaps == 1 {
		return &fmap, &fmapMetadata, nil
	}
	return nil, nil, errSigNotFound
}

// Write overwrites the fmap in the flash file.
func Write(f io.WriteSeeker, fmap *FMap, m *Metadata) error {
	if _, err := f.Seek(int64(m.Start), io.SeekStart); err != nil {
		return err
	}
	if err := binary.Write(f, binary.LittleEndian, fmap.Header); err != nil {
		return err
	}
	return binary.Write(f, binary.LittleEndian, fmap.Areas)
}

// IndexOfArea returns the index of an area in the fmap given its name. If no
// names match, -1 is returned.
func (f *FMap) IndexOfArea(name string) int {
	for i := 0; i < len(f.Areas); i++ {
		if f.Areas[i].Name.String() == name {
			return i
		}
	}
	return -1
}

// ReadArea reads an area from the flash image as a byte array given its index.
func (f *FMap) ReadArea(r io.ReaderAt, i int) ([]byte, error) {
	if i < 0 || int(f.NAreas) <= i {
		return nil, fmt.Errorf("area index %d out of range", i)
	}
	buf := make([]byte, f.Areas[i].Size)
	_, err := r.ReadAt(buf, int64(f.Areas[i].Offset))
	return buf, err
}

// ReadAreaByName is the same as ReadArea but uses the area's name.
func (f *FMap) ReadAreaByName(r io.ReaderAt, name string) ([]byte, error) {
	i := f.IndexOfArea(name)
	if i == -1 {
		return nil, fmt.Errorf("FMAP area %q not found", name)
	}
	return f.ReadArea(r, i)
}

// WriteArea writes a byte array to an area on the flash image given its index.
// If the data is too large for the fmap area, the write is not performed and
// an error returned. If the data is too small, the remainder is left untouched.
func (f *FMap) WriteArea(r io.WriterAt, i int, data []byte) error {
	if i < 0 || int(f.NAreas) <= i {
		return fmt.Errorf("Area index %d out of range", i)
	}
	if uint32(len(data)) > f.Areas[i].Size {
		return fmt.Errorf("data too large for fmap area: %#x > %#x",
			len(data), f.Areas[i].Size)
	}
	_, err := r.WriteAt(data, int64(f.Areas[i].Offset))
	return err
}

// WriteAreaByName is the same as WriteArea but uses the area's name.
func (f *FMap) WriteAreaByName(r io.WriterAt, name string, data []byte) error {
	i := f.IndexOfArea(name)
	if i == -1 {
		return fmt.Errorf("FMAP area %q not found", name)
	}
	return f.WriteArea(r, i, data)
}

// Checksum performs a hash of the static areas.
func (f *FMap) Checksum(r io.ReaderAt, h hash.Hash) ([]byte, error) {
	for i, v := range f.Areas {
		if v.Flags&FmapAreaStatic == 0 {
			continue
		}
		areaReader, err := f.ReadArea(r, i)
		if err != nil {
			return nil, err
		}
		_, err = bytes.NewReader(areaReader).WriteTo(h)
		if err != nil {
			return nil, err
		}
	}
	return h.Sum([]byte{}), nil
}
