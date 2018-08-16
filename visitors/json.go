package visitors

import (
	"encoding/json"
	"fmt"

	"github.com/linuxboot/fiano/uefi"
)

// JSON prints any Firmware node as JSON.
type JSON struct{}

// json package already operates recursively.
func printJSON(ast uefi.Firmware) error {
	b, err := json.MarshalIndent(ast, "", "\t")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// VisitImage applies the JSON visitor to FlashImage.
func (v *JSON) VisitImage(i *uefi.FlashImage) error {
	return printJSON(i)
}

// VisitFV applies the JSON visitor to FirmwareVolume.
func (v *JSON) VisitFV(fv *uefi.FirmwareVolume) error {
	return printJSON(fv)
}

// VisitFile applies the JSON visitor to File.
func (v *JSON) VisitFile(f *uefi.File) error {
	return printJSON(f)
}

// VisitSection applies the JSON visitor to Section.
func (v *JSON) VisitSection(s *uefi.Section) error {
	return printJSON(s)
}

// VisitIFD applies the Find visitor on a FlashDescriptor.
func (v *JSON) VisitIFD(fd *uefi.FlashDescriptor) error {
	return printJSON(fd)
}

// VisitBIOSRegion applies the Find visitor on a BIOSRegion.
func (v *JSON) VisitBIOSRegion(br *uefi.BIOSRegion) error {
	return printJSON(br)
}

// VisitMERegion applies the Find visitor on a MERegion.
func (v *JSON) VisitMERegion(me *uefi.MERegion) error {
	return printJSON(me)
}

// VisitGBERegion applies the Find visitor on a GBERegion.
func (v *JSON) VisitGBERegion(gbe *uefi.GBERegion) error {
	return printJSON(gbe)
}

// VisitPDRegion applies the Find visitor on a PDRegion.
func (v *JSON) VisitPDRegion(pd *uefi.PDRegion) error {
	return printJSON(pd)
}

func init() {
	RegisterCLI("json", 0, func(args []string) (uefi.Visitor, error) {
		return &JSON{}, nil
	})
}
