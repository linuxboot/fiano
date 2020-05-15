// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

// PositionUpdater updates the position of the varisous firmwares in memory
type PositionUpdater struct {
	Scan      bool
	Layout    bool
	Depth     int
	indent    int
	offset    uint64
	curOffset uint64
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *PositionUpdater) Run(f Firmware) error {
	return f.Apply(v)
}

// Visit applies the Table visitor to any Firmware type.
func (v *PositionUpdater) Visit(f Firmware) error {
	var offset uint64
	switch f := f.(type) {
	case *FlashImage:
		if v.Depth > 0 { // Depth <= 0 means all
			v.Depth++
		}
		return v.GoDeeper(f, 0)
	case *FirmwareVolume:
		f.AbsOffSet = v.offset + f.FVOffset
		return v.GoDeeper(f, v.offset+f.FVOffset+f.DataOffset)
	case *File:
		f.AbsOffSet = v.curOffset
		return v.GoDeeper(f, v.curOffset+f.DataOffset)
	case *Section:
		f.AbsOffSet = v.curOffset

		// Reset offset to O for (compressed) section content
		return v.GoDeeper(f, 0)
	case *FlashDescriptor:
		f.AbsOffSet = 0
		return v.GoDeeper(f, 0)
	case *BIOSRegion:
		if f.FRegion != nil {
			offset = uint64(f.FRegion.BaseOffset())
			f.AbsOffSet = offset
		}
		return v.GoDeeper(f, offset)
	case *BIOSPadding:
		f.AbsOffSet = v.offset + f.Offset
		return v.GoDeeper(f, 0)
	case *NVarStore:
		f.AbsOffSet = v.curOffset
		return v.GoDeeper(f, v.curOffset)
	case *NVar:
		f.AbsOffSet = v.curOffset
		return v.GoDeeper(f, v.curOffset+uint64(f.DataOffset))
	case *MERegion:
		if f.FRegion != nil {
			offset = uint64(f.FRegion.BaseOffset())
			f.AbsOffSet = offset
		}
		return v.GoDeeper(f, offset)
	case *MEFPT:
		f.AbsOffSet = v.offset
		return v.GoDeeper(f, 0)
	case *RawRegion:
		if f.FRegion != nil {
			offset = uint64(f.FRegion.BaseOffset())
			f.AbsOffSet = offset
		}
		return v.GoDeeper(f, offset)
	default:
		return v.GoDeeper(f, 0)
	}
}

// GoDeeper runs ApplyChildren and tracks the tree depth and indent
func (v *PositionUpdater) GoDeeper(f Firmware, dataOffset uint64) error {
	// Prepare data and print
	length := uint64(len(f.Buf()))

	v2 := *v
	v2.indent++
	v2.offset = dataOffset
	v2.curOffset = v2.offset

	// Compute offset and visit children
	if v.Depth <= 0 || v.indent < v.Depth {
		if err := f.ApplyChildren(&v2); err != nil {
			return err
		}
	}
	v.curOffset += length

	return nil
}
