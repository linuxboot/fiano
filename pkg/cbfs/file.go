// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/compression"
)

var CbfsHeaderMagicNotFound = errors.New("CBFS header magic doesn't match")

func (f *File) MarshalJSON() ([]byte, error) {
	return json.Marshal(mFile{
		Name:        f.Name,
		Start:       f.RecordStart,
		Size:        f.FileHeader.Size,
		Type:        f.FileHeader.Type.String(),
		Compression: f.Compression().String(),
	})
}

// NewFile reads in the CBFS file at current offset
// On success it seeks to the end of the file.
// On error the current offset withing the ReadSeeker is undefined.
func NewFile(r io.ReadSeeker) (*File, error) {
	var f File
	off, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	f.RecordStart = uint32(off)

	err = Read(r, &f.FileHeader)
	if err != nil {
		return nil, err
	}
	if string(f.Magic[:]) != FileMagic {
		return nil, CbfsHeaderMagicNotFound
	}
	Debug("Found CBFS file at %#02x is %v type %v", f.RecordStart, f, f.Type)

	var nameSize uint32
	if f.AttrOffset == 0 {
		nameSize = f.SubHeaderOffset - uint32(binary.Size(FileHeader{}))
	} else {
		nameSize = f.AttrOffset - uint32(binary.Size(FileHeader{}))
	}
	if err := ReadName(r, &f, nameSize); err != nil {
		return nil, err
	}
	if err := ReadAttributes(r, &f); err != nil {
		return nil, err
	}
	if err := ReadData(r, &f); err != nil {
		return nil, err
	}

	return &f, nil
}

// ReadName reads the variable length CBFS name.
func ReadName(r io.Reader, f *File, size uint32) error {
	b := make([]byte, size)
	n, err := r.Read(b)
	if err != nil {
		Debug("ReadName failed:%v", err)
		return err
	}
	fname := cleanString(string(b))
	Debug("ReadName gets '%s' (%#02x)", fname, b)
	if n != len(b) {
		err = fmt.Errorf("ReadName: got %d, want %d for name", n, len(b))
		Debug("ReadName short: %v", err)
		return err
	}
	// discard trailing NULLs
	z := bytes.Split(b, []byte{0})
	Debug("ReadName stripped: '%s'", z)
	f.Name = string(z[0])
	return nil
}

// ReadAttributes reads the variable length CBFS attribute list.
func ReadAttributes(r io.Reader, f *File) error {
	if f.AttrOffset == 0 {
		return nil
	}

	b := make([]byte, f.SubHeaderOffset-f.AttrOffset)
	n, err := r.Read(b)
	if err != nil {
		Debug("ReadAttributes failed:%v", err)
		return err
	}
	Debug("ReadAttributes gets %#02x", b)
	if n != len(b) {
		err = fmt.Errorf("ReadAttributes: got %d, want %d for name", n, len(b))
		Debug("ReadAttributes short: %v", err)
		return err
	}
	f.Attr = b
	return nil
}

// ReadData reads the variable length CBFS file data.
func ReadData(r io.ReadSeeker, f *File) error {
	Debug("ReadData: Seek to %#x", int64(f.RecordStart+f.SubHeaderOffset))
	if _, err := r.Seek(int64(f.RecordStart+f.SubHeaderOffset), io.SeekStart); err != nil {
		return err
	}
	Debug("ReadData: read %#x", f.Size)
	b := make([]byte, f.Size)
	n, err := r.Read(b)
	if err != nil {
		Debug("ReadData failed:%v", err)
		return err
	}
	f.FData = b
	Debug("ReadData gets %#02x", n)
	return nil
}

// FindAttribute returns the attribute with given tag as
// []byte. It has the size as specified by the tag.
// Returns an error if not found or could not read in total.
func (f *File) FindAttribute(t Tag) ([]byte, error) {
	buf := bytes.NewReader(f.Attr)
	generic := FileAttr{}

	for {
		if err := binary.Read(buf, Endian, &generic); err != nil {
			return nil, err
		}
		if generic.Tag == uint32(Unused) || generic.Tag == uint32(Unused2) {
			return nil, fmt.Errorf("end tag found")
		}
		// Validate input
		if generic.Size < uint32(binary.Size(generic)) || generic.Size == 0xffffffff {
			return nil, fmt.Errorf("tag is malformed, aborting")
		}
		Debug("FindAttribute: Found attribute with tag %x", generic.Tag)

		if Tag(generic.Tag) == t {
			_, _ = buf.Seek(-int64(binary.Size(generic)), io.SeekCurrent)

			ret := make([]byte, generic.Size)
			err := binary.Read(buf, Endian, &ret)
			return ret, err
		} else {
			_, err := buf.Seek(int64(generic.Size)-int64(binary.Size(generic)), io.SeekCurrent)
			if err != nil {
				return nil, err
			}
		}
	}
}

// Compression returns the algorithm used to compress FData.
// If no compression attribute is found or on error it returns 'None'
func (f *File) Compression() Compression {
	cattr, err := f.FindAttribute(Compressed)
	if err != nil {
		Debug("Compression: No compression tag found: %v", err)
		return None
	}

	comp := FileAttrCompression{}
	if err := binary.Read(bytes.NewBuffer(cattr), Endian, &comp); err != nil {
		Debug("Compression: failed to read compression tag: %v", err)
		return None
	}
	return comp.Compression
}

// Decompress returns the decompressed FData
// If FData is not compressed it returns FData
func (f *File) Decompress() ([]byte, error) {
	c := f.Compression()
	if c == None {
		return f.FData, nil
	} else if c == LZMA {
		compressor := compression.LZMA{}
		return compressor.Decode(f.FData)
	} else if c == LZ4 {
		compressor := compression.LZ4{}
		return compressor.Decode(f.FData)
	}
	return nil, fmt.Errorf("unknown compression")
}
