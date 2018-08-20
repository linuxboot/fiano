package visitors

import (
	"io/ioutil"
	"os"

	"github.com/linuxboot/fiano/uefi"
)

// Extract prints any Firmware node as Extract.
// TODO: it would be better to make the Extract interface method a visitor
// itself.
type Extract struct {
	DirPath string
}

func (v *Extract) extract(f uefi.Firmware) error {
	// Create the directory if it does not exist.
	if err := os.MkdirAll(v.DirPath, 0755); err != nil {
		return err
	}

	// Change working directory so we can use relative paths.
	// TODO: commands after this in the pipeline are in unexpected directory
	if err := os.Chdir(v.DirPath); err != nil {
		return err
	}

	f.Extract(".")

	// Output summary json.
	json, err := uefi.MarshalFirmware(f)
	if err != nil {
		return err
	}
	return ioutil.WriteFile("summary.json", json, 0666)
}

// VisitImage applies the Extract visitor to FlashImage.
func (v *Extract) VisitImage(i *uefi.FlashImage) error {
	return v.extract(i)
}

// VisitFV applies the Extract visitor to FirmwareVolume.
func (v *Extract) VisitFV(fv *uefi.FirmwareVolume) error {
	return v.extract(fv)
}

// VisitFile applies the Extract visitor to File.
func (v *Extract) VisitFile(f *uefi.File) error {
	return v.extract(f)
}

// VisitSection applies the Extract visitor to Section.
func (v *Extract) VisitSection(s *uefi.Section) error {
	return v.extract(s)
}

// VisitIFD applies the Extract visitor on a FlashDescriptor.
func (v *Extract) VisitIFD(fd *uefi.FlashDescriptor) error {
	return v.extract(fd)
}

// VisitBIOSRegion applies the Extract visitor on a BIOSRegion.
func (v *Extract) VisitBIOSRegion(br *uefi.BIOSRegion) error {
	return v.extract(br)
}

// VisitMERegion applies the Extract visitor on a MERegion.
func (v *Extract) VisitMERegion(me *uefi.MERegion) error {
	return v.extract(me)
}

// VisitGBERegion applies the Extract visitor on a GBERegion.
func (v *Extract) VisitGBERegion(gbe *uefi.GBERegion) error {
	return v.extract(gbe)
}

// VisitPDRegion applies the Extract visitor on a PDRegion.
func (v *Extract) VisitPDRegion(pd *uefi.PDRegion) error {
	return v.extract(pd)
}

func init() {
	RegisterCLI("extract", 1, func(args []string) (uefi.Visitor, error) {
		return &Extract{
			DirPath: args[0],
		}, nil
	})
}
