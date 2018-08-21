package visitors

import (
	"io/ioutil"
	"regexp"

	"github.com/linuxboot/fiano/uefi"
)

// ReplacePE32 replaces PE32 sections with NewPE32. It must be applied to a
// File to have any effect.
type ReplacePE32 struct {
	// Input
	NewPE32 []byte
}

// VisitImage applies the ReplacePE32 visitor on a FlashImage.
func (v *ReplacePE32) VisitImage(i *uefi.FlashImage) error {
	return nil
}

// VisitFV applies the ReplacePE32 visitor on a FirmwareVolume.
func (v *ReplacePE32) VisitFV(fv *uefi.FirmwareVolume) error {
	return nil
}

// VisitFile applies the ReplacePE32 visitor on a File.
func (v *ReplacePE32) VisitFile(f *uefi.File) error {
	return f.ApplyChildren(v)
}

// VisitSection applies the ReplacePE32 visitor on a Section.
func (v *ReplacePE32) VisitSection(s *uefi.Section) error {
	if s.Header.Type == uefi.SectionTypePE32 {
		s.Buf = append(s.Buf[:s.HeaderSize], v.NewPE32...)
	}
	return s.ApplyChildren(v)
}

// VisitIFD applies the ReplacePE32 visitor on a FlashDescriptor.
func (v *ReplacePE32) VisitIFD(fd *uefi.FlashDescriptor) error {
	return nil
}

// VisitBIOSRegion applies the ReplacePE32 visitor on a BIOSRegion.
func (v *ReplacePE32) VisitBIOSRegion(br *uefi.BIOSRegion) error {
	return nil
}

// VisitMERegion applies the ReplacePE32 visitor on a MERegion.
func (v *ReplacePE32) VisitMERegion(me *uefi.MERegion) error {
	return nil
}

// VisitGBERegion applies the ReplacePE32 visitor on a GBERegion.
func (v *ReplacePE32) VisitGBERegion(gbe *uefi.GBERegion) error {
	return nil
}

// VisitPDRegion applies the ReplacePE32 visitor on a PDRegion.
func (v *ReplacePE32) VisitPDRegion(pd *uefi.PDRegion) error {
	return nil
}

func init() {
	RegisterCLI("replace_pe32", 2, func(args []string) (uefi.Visitor, error) {
		searchRE, err := regexp.Compile(args[0])
		if err != nil {
			return nil, err
		}

		filename := args[1]
		newPE32, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}

		// Find all the matching files and replace their inner PE32s.
		return &Find{
			Predicate: func(f *uefi.File, name string) bool {
				if searchRE.MatchString(name) || searchRE.MatchString(f.Header.UUID.String()) {
					f.Apply(&ReplacePE32{
						NewPE32: newPE32,
					})
					return true
				}
				return false
			},
		}, nil
	})
}
