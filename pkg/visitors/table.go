// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// Table prints the GUIDS, types and sizes as a compact table.
type Table struct {
	W      io.Writer
	TW     *tabwriter.Writer
	indent int
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Table) Run(f uefi.Firmware) error {
	return f.Apply(v)
}

// TODO: move to uefi
// TODO: dedup
func ToString(f uefi.Firmware) string {
	switch f := f.(type) {
	case *uefi.FlashImage:
		return fmt.Sprintf("%v %v %v %#8x", "Image", "", "", len(f.Buf()))
	case *uefi.FirmwareVolume:
		return fmt.Sprintf("%v %v %v %#8x", "FV", f.FileSystemGUID.String(), "", len(f.Buf()))
	case *uefi.File:
		return fmt.Sprintf("%v %v %v %#8x", "File", f.Header.GUID.String(), f.Header.Type, len(f.Buf()))
	case *uefi.Section:
		return fmt.Sprintf("%v %v %v %#8x", "Sec", f.String(), f.Type, len(f.Buf()))
	case *uefi.FlashDescriptor:
		return fmt.Sprintf("%v %v %v %#8x", "IFD", "", "", len(f.Buf()))
	case *uefi.BIOSRegion:
		return fmt.Sprintf("%v %v %v %#8x", "BIOS", "", "", len(f.Buf()))
	case *uefi.BIOSPadding:
		return fmt.Sprintf("%v %v %v %#8x", "BIOS Pad", "", "", len(f.Buf()))
	case *uefi.RawRegion:
		return fmt.Sprintf("%v %v %v %#8x", f.Type().String(), "", "", len(f.Buf()))
	default:
		return fmt.Sprintf("%v %v %v %#8x", fmt.Sprintf("%T", f), "", "")
	}
}

// Visit applies the Table visitor to any Firmware type.
func (v *Table) Visit(f uefi.Firmware) error {
	switch f := f.(type) {
	case *uefi.FlashImage:
		return v.printRow(f, "Image", "", "")
	case *uefi.FirmwareVolume:
		return v.printRow(f, "FV", f.FileSystemGUID.String(), "")
	case *uefi.File:
		// TODO: make name part of the file node
		return v.printRow(f, "File", f.Header.GUID.String(), f.Header.Type)
	case *uefi.Section:
		return v.printRow(f, "Sec", f.String(), f.Type)
	case *uefi.FlashDescriptor:
		return v.printRow(f, "IFD", "", "")
	case *uefi.BIOSRegion:
		return v.printRow(f, "BIOS", "", "")
	case *uefi.BIOSPadding:
		return v.printRow(f, "BIOS Pad", "", "")
	case *uefi.RawRegion:
		return v.printRow(f, f.Type().String(), "", "")
	default:
		return v.printRow(f, fmt.Sprintf("%T", f), "", "")
	}
}

func indent(n int) string {
	return strings.Repeat(" ", n)
}

func (v *Table) printRow(f uefi.Firmware, node, name, typez interface{}) error {
	if v.TW == nil {
		v.TW = tabwriter.NewWriter(v.W, 0, 0, 2, ' ', 0)
		defer func() { v.TW.Flush() }()
		fmt.Fprintf(v.TW, "%sNode\tGUID/Name\tType\tSize\n", indent(v.indent))
	}
	fmt.Fprintf(v.TW, "%s%v\t%v\t%v\t%#8x\n", indent(v.indent), node, name, typez, len(f.Buf()))
	v2 := *v
	v2.indent++
	if err := f.ApplyChildren(&v2); err != nil {
		return err
	}
	if fv, ok := f.(*uefi.FirmwareVolume); ok {
		// Print free space at the end of the volume
		fmt.Fprintf(v.TW, "%s%v\t%v\t%v\t%#8x\n", indent(v2.indent), "Free", "", "", fv.FreeSpace)
	}
	return nil
}

func init() {
	RegisterCLI("table", "print out important information in a pretty table", 0, func(args []string) (uefi.Visitor, error) {
		return &Table{
			W: Stdout,
		}, nil
	})
}
