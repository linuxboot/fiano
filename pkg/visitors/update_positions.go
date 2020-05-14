// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"github.com/linuxboot/fiano/pkg/uefi"
)

// positionUpdater updates the position of the varisous firmwares in memory
type positionUpdater struct {
	Scan      bool
	Layout    bool
	Depth     int
	indent    int
	offset    uint64
	curOffset uint64
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *positionUpdater) Run(f uefi.Firmware) error {
	return f.Apply(v)
}

// Visit applies the Table visitor to any Firmware type.
func (v *positionUpdater) Visit(f uefi.Firmware) error {
	var offset uint64
	switch f := f.(type) {
	case *uefi.FlashImage:
		if v.Depth > 0 { // Depth <= 0 means all
			v.Depth++
		}
		return v.GoDeeper(f, 0)
	case *uefi.FirmwareVolume:
		f.AbsOffSet = v.offset + f.FVOffset
		return v.GoDeeper(f, v.offset+f.FVOffset+f.DataOffset)
	case *uefi.File:
		f.AbsOffSet = v.curOffset
		return v.GoDeeper(f, v.curOffset+f.DataOffset)
	case *uefi.Section:
		f.AbsOffSet = v.curOffset

		// Reset offset to O for (compressed) section content
		return v.GoDeeper(f, 0)
	case *uefi.FlashDescriptor:
		f.AbsOffSet = 0
		return v.GoDeeper(f, 0)
	case *uefi.BIOSRegion:
		if f.FRegion != nil {
			offset = uint64(f.FRegion.BaseOffset())
			f.AbsOffSet = offset
		}
		return v.GoDeeper(f, offset)
	case *uefi.BIOSPadding:
		f.AbsOffSet = v.offset + f.Offset
		return v.GoDeeper(f, 0)
	case *uefi.NVarStore:
		f.AbsOffSet = v.curOffset
		return v.GoDeeper(f, v.curOffset)
	case *uefi.NVar:
		f.AbsOffSet = v.curOffset
		return v.GoDeeper(f, v.curOffset+uint64(f.DataOffset))
	case *uefi.MERegion:
		if f.FRegion != nil {
			offset = uint64(f.FRegion.BaseOffset())
			f.AbsOffSet = offset
		}
		return v.GoDeeper(f, offset)
	case *uefi.MEFPT:
		f.AbsOffSet = v.offset
		return v.GoDeeper(f, 0)
	case *uefi.RawRegion:
		if f.FRegion != nil {
			offset = uint64(f.FRegion.BaseOffset())
			f.AbsOffSet = offset
		}
		return v.GoDeeper(f, offset)
	default:
		return v.GoDeeper(f, 0)
	}
}

func (v *positionUpdater) GoDeeper(f uefi.Firmware, dataOffset uint64) error {
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
