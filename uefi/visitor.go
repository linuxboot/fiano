package uefi

// Visitor represents an operation which can be applied to the Firmware. To
// implement a visitor, implement a method for each concrete Firmware type you
// want to visit. The remaining nodes can be recursed over automatically with:
//
//     func (v *Find) VisitFV(fv *uefi.FirmwareVolume) error {
//             return fv.ApplyChildren(v)
//     }
//
// Or pruned with:
//
//     func (v *Find) VisitFV(fv *uefi.FirmwareVolume) error {
//             return nil
//     }
type Visitor interface {
	VisitImage(*FlashImage) error
	VisitFV(*FirmwareVolume) error
	VisitFile(*File) error
	VisitSection(*Section) error

	// Intel specific
	VisitIFD(*FlashDescriptor) error
	VisitBIOSRegion(*BIOSRegion) error
	VisitMERegion(*MERegion) error
	VisitGBERegion(*GBERegion) error
	VisitPDRegion(*PDRegion) error
}
