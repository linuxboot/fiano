package visitors

import (
	"fmt"

	"github.com/linuxboot/fiano/uefi"
)

// Remove a firmware file given its GUID.
type Remove struct {
	// Input
	MaxMatches int
	Predicate  func(f *uefi.File) bool

	// Output
	Matches []*uefi.File
}

// VisitImage applies the Remove visitor on a FlashImage.
func (v *Remove) VisitImage(i *uefi.FlashImage) error {
	return i.ApplyChildren(v)
}

// VisitFV applies the Remove visitor on a FirmwareVolume.
func (v *Remove) VisitFV(fv *uefi.FirmwareVolume) error {
	for i := 0; i < len(fv.Files); i++ {
		if v.Predicate(fv.Files[i]) {
			v.Matches = append(v.Matches, fv.Files[i+1])
			if len(v.Matches) > v.MaxMatches {
				return fmt.Errorf("found more than %d files to remove", v.MaxMatches)
			}
			fv.Files = append(fv.Files[:i], fv.Files[i+1:]...)
		}
	}
	return fv.ApplyChildren(v)
}

// VisitFile applies the Remove visitor on a File.
func (v *Remove) VisitFile(f *uefi.File) error {
	return f.ApplyChildren(v)
}

// VisitSection applies the Remove visitor on a Section.
func (v *Remove) VisitSection(s *uefi.Section) error {
	return s.ApplyChildren(v)
}

// VisitIFD applies the Remove visitor on a FlashDescriptor.
func (v *Remove) VisitIFD(fd *uefi.FlashDescriptor) error {
	return fd.ApplyChildren(v)
}

// VisitBIOSRegion applies the Remove visitor on a BIOSRegion.
func (v *Remove) VisitBIOSRegion(br *uefi.BIOSRegion) error {
	return br.ApplyChildren(v)
}

// VisitMERegion applies the Remove visitor on a MERegion.
func (v *Remove) VisitMERegion(me *uefi.MERegion) error {
	return me.ApplyChildren(v)
}

// VisitGBERegion applies the Remove visitor on a GBERegion.
func (v *Remove) VisitGBERegion(gbe *uefi.GBERegion) error {
	return gbe.ApplyChildren(v)
}

// VisitPDRegion applies the Remove visitor on a PDRegion.
func (v *Remove) VisitPDRegion(pd *uefi.PDRegion) error {
	return pd.ApplyChildren(v)
}

func init() {
	RegisterCLI("remove", 1, func(args []string) (uefi.Visitor, error) {
		searchGUID := args[0]
		return &Remove{
			MaxMatches: 1,
			Predicate: func(f *uefi.File) bool {
				return f.Header.UUID.String() == searchGUID
			},
		}, nil
	})
}
