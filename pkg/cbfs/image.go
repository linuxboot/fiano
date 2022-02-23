// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/linuxboot/fiano/pkg/fmap"
)

type SegReader struct {
	Type FileType
	New  func(f *File) (ReadWriter, error)
	Name string
}

var SegReaders = make(map[FileType]*SegReader)

func RegisterFileReader(f *SegReader) error {
	if r, ok := SegReaders[f.Type]; ok {
		return fmt.Errorf("RegisterFileType: Slot of %v is owned by %s, can't add %s", r.Type, r.Name, f.Name)
	}
	SegReaders[f.Type] = f
	Debug("Registered %v", f)
	return nil
}

func NewImage(rs io.ReadSeeker) (*Image, error) {
	// Suck the image in. Todo: write a thing that implements
	// ReadSeeker on a []byte.
	b, err := ioutil.ReadAll(rs)
	if err != nil {
		return nil, fmt.Errorf("ReadAll: %v", err)
	}
	in := bytes.NewReader(b)
	f, m, err := fmap.Read(in)
	if err != nil {
		return nil, err
	}
	Debug("Fmap %v", f)
	var i = &Image{FMAP: f, FMAPMetadata: m, Data: b}
	for _, a := range f.Areas {
		Debug("Check %v", a.Name.String())
		if a.Name.String() == "COREBOOT" {
			i.Area = &a
			break
		}
	}
	if i.Area == nil {
		return nil, fmt.Errorf("No CBFS in fmap")
	}
	r := io.NewSectionReader(in, int64(i.Area.Offset), int64(i.Area.Size))

	for off := int64(0); off < int64(i.Area.Size); {
		var f File
		if _, err := r.Seek(off, io.SeekStart); err != nil {
			return nil, err
		}
		err := Read(r, &f.FileHeader)
		if err == io.EOF {
			return i, nil
		}
		if err != nil {
			return nil, err
		}
		if string(f.Magic[:]) != FileMagic {
			off += 16
			continue
		}
		Debug("It is %v type %v", f, f.Type)
		f.RecordStart = uint32(off)
		Debug("Starting at %#02x + %#02x", i.Area.Offset, f.RecordStart)
		nameStart, err := r.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("Getting file offset for name: %v", err)
		}
		sr, ok := SegReaders[f.Type]
		// If we cant find any new match, break out of the loop.
		if !ok {
			// Remove last segment in image, because it's garbage
			i.Segs = i.Segs[:len(i.Segs)-1]
			break
		}
		var nameSize uint32
		if f.AttrOffset == 0 {
			nameSize = f.SubHeaderOffset - (uint32(nameStart) - f.RecordStart)
		} else {
			nameSize = f.AttrOffset - (uint32(nameStart) - f.RecordStart)
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
		Debug("Found a SegReader for this %d size section: %v", f.Size, f.Name)
		s, err := sr.New(&f)
		if err != nil {
			return nil, err
		}
		if err := s.Read(bytes.NewReader(f.FData)); err != nil {
			return nil, fmt.Errorf("Reading %#x byte subheader: %v", len(f.FData), err)
		}
		Debug("Segment was readable")
		i.Segs = append(i.Segs, s)
		off, err = r.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, err
		}
		// Force alignment.
		off = (off + 15) & (^15)

	}
	return i, nil
}

func (i *Image) WriteFile(name string, perm os.FileMode) error {
	if err := ioutil.WriteFile(name, i.Data, 0666); err != nil {
		return err
	}
	return nil
}

// Update creates a new []byte for the cbfs. It is complicated a lot
// by the fact that endianness is not consistent in cbfs images.
func (i *Image) Update() error {
	//FIXME: Support additional regions
	for _, s := range i.Segs {
		var b bytes.Buffer
		if err := Write(&b, s.GetFile().FileHeader); err != nil {
			return err
		}
		if _, err := b.Write(s.GetFile().Attr); err != nil {
			return fmt.Errorf("Writing attr to cbfs record for %v: %v", s, err)
		}
		if err := s.Write(&b); err != nil {
			return err
		}
		// This error should not happen but we need to check just in case.
		end := uint32(len(b.Bytes())) + s.GetFile().RecordStart
		if end > i.Area.Size {
			return fmt.Errorf("Region [%#x, %#x] outside of CBFS [%#x, %#x]", s.GetFile().RecordStart, end, s.GetFile().RecordStart, i.Area.Size)
		}

		Debug("Copy %s %d bytes to i.Data[%d]", s.GetFile().Type.String(), len(b.Bytes()), i.Area.Offset+s.GetFile().RecordStart)
		copy(i.Data[i.Area.Offset+s.GetFile().RecordStart:], b.Bytes())
	}
	return nil
}

type mImage struct {
	Segments []ReadWriter
}

func (i *Image) MarshalJSON() ([]byte, error) {
	return json.Marshal(mImage{Segments: i.Segs})
}

func (i *Image) String() string {
	var s = "FMAP REGIOName: COREBOOT\n"

	s += fmt.Sprintf("%-32s %-8s   %-24s %-8s   %-4s\n", "Name", "Offset", "Type", "Size", "Comp")
	for _, seg := range i.Segs {
		s = s + seg.String() + "\n"
	}
	return s
}

func (h *FileHeader) Deleted() bool {
	t := h.Type
	return t == TypeDeleted || t == TypeDeleted2
}

func (i *Image) Remove(n string) error {
	found := -1
	for x, s := range i.Segs {
		if s.GetFile().Name == n {
			found = x
		}
	}
	if found == -1 {
		return os.ErrExist
	}
	// You can not remove the master header
	// Just remake the cbfs if you're doing that kind of surgery.
	if found == 0 {
		return os.ErrPermission
	}
	// Bootblock on x86 is at the end of CBFS and shall stay untouched.
	if found == len(i.Segs)-1 && i.Segs[found].GetFile().Type == TypeBootBlock {
		return os.ErrPermission
	}
	start, end := found, found+1
	if i.Segs[start-1].GetFile().Deleted() {
		start = start - 1
	}
	if i.Segs[end].GetFile().Deleted() {
		end = end + 1
	}
	Debug("Remove: empty range [%d:%d]", start, end)
	base := i.Segs[start].GetFile().RecordStart
	top := i.Segs[end].GetFile().RecordStart
	Debug("Remove: base %#x top %#x", base, top)
	// 0x28: header size + 16-byte-aligned-size name
	s := top - base - 0x28
	i.Segs[found].GetFile().SubHeaderOffset = 0x28
	i.Segs[found].GetFile().Size = s
	del, _ := NewEmptyRecord(i.Segs[found].GetFile())
	Debug("Offset is 0x28, Size is %#x", s)
	Debug("Remove: Replace %d..%d with %s", start, end, del.String())
	// At most, there will be an Empty record before us since
	// things come pre-merged
	i.Segs = append(append(i.Segs[:start], del), i.Segs[end:]...)
	return nil
}
