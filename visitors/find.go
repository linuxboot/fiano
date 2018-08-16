package visitors

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"

	"github.com/linuxboot/fiano/uefi"
)

// Find a firmware file given its name or GUID.
type Find struct {
	// Input
	// Only when this functions returns true will the file appear in the
	// `Matches` slice.
	Predicate func(f *uefi.File, name string) bool

	// Output
	Matches []*uefi.File

	// Private
	currentFile *uefi.File
}

// VisitImage applies the Find visitor on a FlashImage.
func (v *Find) VisitImage(i *uefi.FlashImage) error {
	return i.ApplyChildren(v)
}

// VisitFV applies the Find visitor on a FirmwareVolume.
func (v *Find) VisitFV(fv *uefi.FirmwareVolume) error {
	return fv.ApplyChildren(v)
}

// VisitFile applies the Find visitor on a File.
func (v *Find) VisitFile(f *uefi.File) error {
	// Clone the visitor so the `currentFile` is passed only to descendents.
	v2 := &Find{
		Predicate:   v.Predicate,
		currentFile: f,
	}
	err := f.ApplyChildren(v2)
	v.Matches = append(v.Matches, v2.Matches...) // Merge together
	return err
}

// VisitSection applies the Find visitor on a Section.
func (v *Find) VisitSection(s *uefi.Section) error {
	if v.currentFile != nil && v.Predicate(v.currentFile, s.Name) {
		v.Matches = append(v.Matches, v.currentFile)
		v.currentFile = nil // Do not double-match with a sibling.
	}
	return s.ApplyChildren(v)
}

// VisitIFD applies the Find visitor on a FlashDescriptor.
func (v *Find) VisitIFD(fd *uefi.FlashDescriptor) error {
	return fd.ApplyChildren(v)
}

// VisitBIOSRegion applies the Find visitor on a BIOSRegion.
func (v *Find) VisitBIOSRegion(br *uefi.BIOSRegion) error {
	return br.ApplyChildren(v)
}

// VisitMERegion applies the Find visitor on a MERegion.
func (v *Find) VisitMERegion(me *uefi.MERegion) error {
	return me.ApplyChildren(v)
}

// VisitGBERegion applies the Find visitor on a GBERegion.
func (v *Find) VisitGBERegion(gbe *uefi.GBERegion) error {
	return gbe.ApplyChildren(v)
}

// VisitPDRegion applies the Find visitor on a PDRegion.
func (v *Find) VisitPDRegion(pd *uefi.PDRegion) error {
	return pd.ApplyChildren(v)
}

func init() {
	RegisterCLI("find", 1, func(args []string) (uefi.Visitor, error) {
		searchRE, err := regexp.Compile(args[0])
		if err != nil {
			return nil, err
		}
		return &Find{
			Predicate: func(f *uefi.File, name string) bool {
				if searchRE.MatchString(name) || searchRE.MatchString(f.Header.UUID.String()) {
					b, err := json.MarshalIndent(f, "", "\t")
					if err != nil {
						log.Fatal(err)
					}
					fmt.Println(string(b))
					return true
				}
				return false
			},
		}, nil
	})
}
