// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cbnt provides representation of BG/CBnT structures.
package cbnt

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

var (
	endianess = binary.LittleEndian
)

type LayoutProvider interface {
	Layout() []LayoutField
}

// Acts as an accessor for all the methods shared accross the types.
// All types implementing Structure should embed it.
type Common struct{}

func (Common) TotalSize(p LayoutProvider) uint64 {
	var total uint64
	for _, f := range p.Layout() {
		total += f.Size()
	}
	return total
}

func (Common) SizeOf(p LayoutProvider, id int) (uint64, error) {
	for _, f := range p.Layout() {
		if f.ID == id {
			return f.Size(), nil
		}
	}

	return 0, fmt.Errorf("has no field of ID %d", id)
}

func (Common) OffsetOf(p LayoutProvider, id int) (uint64, error) {
	var offset uint64

	for _, f := range p.Layout() {
		if f.ID == id {
			return offset, nil
		}
		offset += f.Size()
	}

	return 0, fmt.Errorf("has no field of ID %d", id)
}

func (Common) PrettyString(depth uint, withHeader bool, p LayoutProvider, structName string, opts ...pretty.Option) string {
	var lines []string

	if withHeader {
		lines = append(lines, pretty.Header(depth, structName, p))
	}

	for _, f := range p.Layout() {
		if f.Type == ManifestFieldList {
			// Handling type detection here would be dirty here, let's not do that and just skip
			// This case is difficult to handle without using reflection (which I really want to avoid),
			// thus this is an exception from generalizing logic and has to be handled by the type itself.
			continue
		}
		lines = append(lines, pretty.SubValue(depth+1, f.Name, "", f.Value(), opts...)...)
	}

	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func (Common) ReadFrom(r io.Reader, p LayoutProvider) (int64, error) {
	totalN := int64(0)

	for _, f := range p.Layout() {
		switch f.Type {
		case ManifestFieldEndValue:
			n, err := readStatic(r, f.Size(), f.Value())
			if err != nil {
				return totalN, fmt.Errorf("unable to read field '%s': %w", f.Name, err)
			}
			totalN += n
		case ManifestFieldArrayDynamicWithSize:
			size := uint16(f.Size())
			n, err := readArrayDynamic(r, &size, f.Value())
			if err != nil {
				return totalN, fmt.Errorf("unable to read field '%s': %w", f.Name, err)
			}
			totalN += n
		case ManifestFieldArrayDynamicWithPrefix:
			n, err := readArrayDynamic(r, nil, f.Value())
			if err != nil {
				return totalN, fmt.Errorf("unable to read field '%s': %w", f.Name, err)
			}
			totalN += n
		case ManifestFieldList:
			if f.ReadList == nil {
				return totalN, fmt.Errorf("field '%s' has no list reader", f.Name)
			}
			n, err := f.ReadList(r)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field '%s': %w", f.Name, err)
			}
			totalN += n
		case ManifestFieldArrayStatic:
			n, err := readStatic(r, f.Size(), f.Value())
			if err != nil {
				return totalN, fmt.Errorf("unable to read field '%s': %w", f.Name, err)
			}
			totalN += n
		case ManifestFieldSubStruct:
			fieldValue := f.Value()
			sub, ok := fieldValue.(io.ReaderFrom)
			if !ok {
				return totalN, fmt.Errorf("field '%s' does not implement io.ReaderFrom", f.Name)
			}
			n, err := readSubStruct(r, sub)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field '%s': %w", f.Name, err)
			}
			totalN += n
		}
	}

	return totalN, nil
}

func (Common) WriteTo(w io.Writer, p LayoutProvider) (int64, error) {
	totalN := int64(0)

	for _, f := range p.Layout() {
		switch f.Type {
		case ManifestFieldEndValue:
			n, err := writeStatic(w, f.Size(), f.Value())
			if err != nil {
				return totalN, fmt.Errorf("unable to write field '%s': %w", f.Name, err)
			}
			totalN += n
		case ManifestFieldArrayDynamicWithSize:
			n, err := writeArrayDynamic(w, false, f.Value())
			if err != nil {
				return totalN, fmt.Errorf("unable to write field '%s': %w", f.Name, err)
			}
			totalN += n
		case ManifestFieldArrayDynamicWithPrefix:
			n, err := writeArrayDynamic(w, true, f.Value())
			if err != nil {
				return totalN, fmt.Errorf("unable to write field '%s': %w", f.Name, err)
			}
			totalN += n
		case ManifestFieldList:
			if f.WriteList == nil {
				return totalN, fmt.Errorf("field '%s' has no list writer", f.Name)
			}
			n, err := f.WriteList(w)
			if err != nil {
				return totalN, fmt.Errorf("unable to write field '%s': %w", f.Name, err)
			}
			totalN += n
		case ManifestFieldArrayStatic:
			n, err := writeStatic(w, f.Size(), f.Value())
			if err != nil {
				return totalN, fmt.Errorf("unable to write field '%s': %w", f.Name, err)
			}
			totalN += n
		case ManifestFieldSubStruct:
			fieldValue := f.Value()
			if fieldValue == nil {
				continue
			}

			sub, ok := fieldValue.(io.WriterTo)
			if !ok {
				return totalN, fmt.Errorf("field '%s' does not implement io.WriterTo", f.Name)
			}
			n, err := writeSubStruct(w, sub)
			if err != nil {
				return totalN, fmt.Errorf("unable to write field '%s': %w", f.Name, err)
			}
			totalN += n
		}
	}

	return totalN, nil

}

// We have 5 possible types of ManifestFieldType:
// endValue, arrayDynamic, arrayStatic, list and subStruct.
// Common.ReadFrom will distingush these (apart from list) and use the helpers.
func readStatic(r io.Reader, fieldSize uint64, fieldValue any) (int64, error) {
	n, err := fieldSize, binary.Read(r, endianess, fieldValue)
	if err != nil {
		return 0, err
	}
	return int64(n), nil
}

func readArrayDynamic(r io.Reader, size *uint16, out any) (int64, error) {
	total := int64(0)

	if size == nil {
		var n uint16
		if err := binary.Read(r, endianess, &n); err != nil {
			return total, err
		}
		total += int64(binary.Size(n))
		size = &n
	}

	dst, ok := out.(*[]byte)
	if !ok {
		return total, fmt.Errorf("arrayDynamic expects *[]byte, got %T", out)
	}

	*dst = make([]byte, *size)
	n := len(*dst)
	if err := binary.Read(r, endianess, *dst); err != nil {
		return total, err
	}
	total += int64(n)

	return total, nil
}

func readSubStruct(r io.Reader, out io.ReaderFrom) (int64, error) {
	n, err := out.ReadFrom(r)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func writeStatic(w io.Writer, fieldSize uint64, fieldValue any) (int64, error) {
	n, err := fieldSize, binary.Write(w, endianess, fieldValue)
	if err != nil {
		return 0, err
	}
	return int64(n), nil
}

func writeArrayDynamic(w io.Writer, withPrefix bool, out any) (int64, error) {
	total := int64(0)

	src, ok := out.(*[]byte)
	if !ok {
		return total, fmt.Errorf("arrayDynamic expects *[]byte, got %T", out)
	}

	if withPrefix {
		size := uint16(len(*src))
		if err := binary.Write(w, endianess, size); err != nil {
			return total, err
		}
		total += int64(binary.Size(size))
	}

	n := len(*src)
	if err := binary.Write(w, endianess, *src); err != nil {
		return total, err
	}
	total += int64(n)

	return total, nil
}

func writeSubStruct(w io.Writer, out io.WriterTo) (int64, error) {
	n, err := out.WriteTo(w)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Okay this might seem bit hacky: we use dummy type that just
// implements LayoutProvider, and based on info value passes
// either full <type> Layout or <type> Layout - StructInfo.
// This is used a lot with BPM types. Not ideal, but
// spares lines of boilerplate code per type.
type DummyLayout struct {
	Fields []LayoutField
}

func (s DummyLayout) Layout() []LayoutField {
	return s.Fields
}

type StructInfo interface {
	Structure
	StructInfo() StructInfo
}

func NewStructInfo(bgv BootGuardVersion) StructInfo {
	switch bgv {
	case Version10:
		s := &StructInfoBG{}
		return s
	case Version20, Version21:
		s := &StructInfoCBNT{}
		return s
	default:
		return nil
	}
}
