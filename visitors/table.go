package visitors

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/linuxboot/fiano/uefi"
)

// Table prints the GUIDS, types and sizes as a compact table.
type Table struct {
	W      *tabwriter.Writer
	indent int
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Table) Run(f uefi.Firmware) error {
	return f.Apply(v)
}

// Visit applies the Table visitor to any Firmware type.
func (v *Table) Visit(f uefi.Firmware) error {
	switch f := f.(type) {
	case *uefi.FlashImage:
		return v.printRow(f, "Image", "", "", "")
	case *uefi.FirmwareVolume:
		return v.printRow(f, "FV", f.FileSystemGUID.String(), "", f.Length)
	case *uefi.File:
		// TODO: make name part of the file node
		return v.printRow(f, "File", f.Header.UUID.String(), f.Header.Type, f.Header.ExtendedSize)
	case *uefi.Section:
		return v.printRow(f, "Sec", f.Name, f.Type, fmt.Sprintf("%d", f.Header.ExtendedSize))
	case *uefi.FlashDescriptor:
		return v.printRow(f, "IFD", "", "", "")
	case *uefi.BIOSRegion:
		return v.printRow(f, "BIOS", "", "", "")
	case *uefi.MERegion:
		return v.printRow(f, "ME", "", "", "")
	case *uefi.GBERegion:
		return v.printRow(f, "GBE", "", "", "")
	case *uefi.PDRegion:
		return v.printRow(f, "PD", "", "", "")
	default:
		return v.printRow(f, fmt.Sprintf("%T", f), "", "", "")
	}
}

func indent(n int) string {
	return strings.Repeat(" ", n)
}

func (v *Table) printRow(f uefi.Firmware, node, name, typez, size interface{}) error {
	if v.W == nil {
		v.W = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		defer func() { v.W.Flush() }()
		fmt.Fprintf(v.W, "%sNode\tGUID/Name\tType\tSize\n", indent(v.indent))
	}
	fmt.Fprintf(v.W, "%s%v\t%v\t%v\t%v\n", indent(v.indent), node, name, typez, size)
	v2 := *v
	v2.indent++
	return f.ApplyChildren(&v2)
}

func init() {
	RegisterCLI("table", 0, func(args []string) (uefi.Visitor, error) {
		return &Table{}, nil
	})
}
