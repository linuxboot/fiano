// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// Table prints the GUIDS, types and sizes as a compact table.
type Table struct {
	W         *tabwriter.Writer
	Layout    bool
	TopLevel  bool
	indent    int
	offset    uint64
	curOffset uint64
	depth     int
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Table) Run(f uefi.Firmware) error {
	return f.Apply(v)
}

// Visit applies the Table visitor to any Firmware type.
func (v *Table) Visit(f uefi.Firmware) error {
	var offset uint64
	switch f := f.(type) {
	case *uefi.FlashImage:
		v.depth = v.indent + 1
		return v.printFirmware(f, "Image", "", "", 0, 0)
	case *uefi.FirmwareVolume:
		return v.printFirmware(f, "FV", f.FileSystemGUID.String(), "", v.offset+f.FVOffset, v.offset+f.FVOffset+f.DataOffset)
	case *uefi.File:
		// TODO: make name part of the file node
		return v.printFirmware(f, "File", f.Header.GUID.String(), f.Header.Type, v.curOffset, v.curOffset+f.DataOffset)
	case *uefi.Section:
		// Reset offset to O for (compressed) section content
		return v.printFirmware(f, "Sec", f.String(), f.Type, v.curOffset, 0)
	case *uefi.FlashDescriptor:
		v.depth = v.indent + 1
		return v.printFirmware(f, "IFD", "", "", 0, 0)
	case *uefi.BIOSRegion:
		v.depth = v.indent + 1
		if f.FRegion != nil {
			offset = uint64(f.FRegion.BaseOffset())
		}
		return v.printFirmware(f, "BIOS", "", "", offset, offset)
	case *uefi.BIOSPadding:
		return v.printFirmware(f, "BIOS Pad", "", "", v.offset+f.Offset, 0)
	case *uefi.NVarStore:
		return v.printFirmware(f, "NVAR Store", "", "", v.curOffset, v.curOffset)
	case *uefi.NVar:
		return v.printFirmware(f, "NVAR", f.GUID.String(), f, v.curOffset, v.curOffset+uint64(f.DataOffset))
	case *uefi.RawRegion:
		v.depth = v.indent + 1
		if f.FRegion != nil {
			offset = uint64(f.FRegion.BaseOffset())
		}
		return v.printFirmware(f, f.Type().String(), "", "", offset, offset)
	default:
		return v.printFirmware(f, fmt.Sprintf("%T", f), "", "", 0, 0)
	}
}

func indent(n int) string {
	return strings.Repeat(" ", n)
}

func (v *Table) printFirmware(f uefi.Firmware, node, name, typez interface{}, offset, dataOffset uint64) error {
	if v.W == nil {
		v.W = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		defer func() { v.W.Flush() }()
		if v.Layout {
			fmt.Fprintf(v.W, "%sNode\tGUID/Name\tOffset\tSize\n", indent(v.indent))
		} else {
			fmt.Fprintf(v.W, "%sNode\tGUID/Name\tType\tSize\n", indent(v.indent))
		}
	}
	length := uint64(len(f.Buf()))
	if typez == "" {
		if uefi.IsErased(f.Buf(), uefi.Attributes.ErasePolarity) {
			typez = "(empty)"
		}
	}
	v.printRow(node, name, typez, offset, length)

	v2 := *v
	v2.indent++
	v2.offset = dataOffset
	v2.curOffset = v2.offset
	if !v.TopLevel || v.indent < v.depth {

		if err := f.ApplyChildren(&v2); err != nil {
			return err
		}
	}
	v.curOffset += length
	switch f := f.(type) {
	case *uefi.FirmwareVolume:
		// Print free space at the end of the volume
		v2.printRow("Free", "", "", offset+length-f.FreeSpace, f.FreeSpace)
	case *uefi.NVarStore:
		// Print free space and GUID store
		v2.printRow("Free", "", "", offset+f.FreeSpaceOffset, f.GUIDStoreOffset-f.FreeSpaceOffset)
		v2.printRow("GUIDStore", "", fmt.Sprintf("%d GUID", len(f.GUIDStore)), offset+f.GUIDStoreOffset, f.Length-f.GUIDStoreOffset)
	case *uefi.File:
		// Align
		// TODO: do we need the complex align logic from assemble?
		v.curOffset = uefi.Align8(v.curOffset)
	}
	return nil
}

func (v *Table) printRow(node, name, typez interface{}, offset, length uint64) {
	if v.Layout {
		if name == "" {
			name = typez
		}
		fmt.Fprintf(v.W, "%s%v\t%v\t%#08x\t%#08x\n", indent(v.indent), node, name, offset, length)
	} else {
		fmt.Fprintf(v.W, "%s%v\t%v\t%v\t%#8x\n", indent(v.indent), node, name, typez, length)
	}
}

func init() {
	RegisterCLI("table", "print out important information in a pretty table", 0, func(args []string) (uefi.Visitor, error) {
		return &Table{}, nil
	})
	RegisterCLI("layout-table", "print out offset and size information of top level firmware volumes in a pretty table", 0, func(args []string) (uefi.Visitor, error) {
		return &Table{Layout: true, TopLevel: true}, nil
	})
	RegisterCLI("layout-table-full", "print out offset and size information in a pretty table", 0, func(args []string) (uefi.Visitor, error) {
		return &Table{Layout: true}, nil
	})
}
