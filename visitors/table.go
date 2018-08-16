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

// VisitImage applies a Table visitor to FlashImage.
func (v *Table) VisitImage(i *uefi.FlashImage) error {
	return v.printRow(i, "Image", "", "", "")
}

// VisitFV applies a Table visitor to FirmwareVolume.
func (v *Table) VisitFV(fv *uefi.FirmwareVolume) error {
	return v.printRow(fv, "FV", fv.FileSystemGUID.String(), "", fv.Length)
}

// VisitFile applies a Table visitor to File.
func (v *Table) VisitFile(f *uefi.File) error {
	// TODO: make name part of the file node
	return v.printRow(f, "File", f.Header.UUID.String(), f.Header.Type, f.Header.ExtendedSize)
}

// VisitSection applies a Table visitor to Section.
func (v *Table) VisitSection(s *uefi.Section) error {
	return v.printRow(s, "Sec", s.Name, s.Type, fmt.Sprintf("%d", s.Header.ExtendedSize))
}

// VisitIFD applies the Table visitor on a FlashDescriptor.
func (v *Table) VisitIFD(fd *uefi.FlashDescriptor) error {
	return v.printRow(fd, "IFD", "", "", "")
}

// VisitBIOSRegion applies the Table visitor on a BIOSRegion.
func (v *Table) VisitBIOSRegion(br *uefi.BIOSRegion) error {
	return v.printRow(br, "BIOS", "", "", "")
}

// VisitMERegion applies the Table visitor on a MERegion.
func (v *Table) VisitMERegion(me *uefi.MERegion) error {
	return v.printRow(me, "ME", "", "", "")
}

// VisitGBERegion applies the Table visitor on a GBERegion.
func (v *Table) VisitGBERegion(gbe *uefi.GBERegion) error {
	return v.printRow(gbe, "GBE", "", "", "")
}

// VisitPDRegion applies the Table visitor on a PDRegion.
func (v *Table) VisitPDRegion(pd *uefi.PDRegion) error {
	return v.printRow(pd, "PD", "", "", "")
}

func init() {
	RegisterCLI("table", 0, func(args []string) (uefi.Visitor, error) {
		return &Table{}, nil
	})
}
