package consts

const (
	// BasePhysAddr is the absolute physical address where the firmware image ends.
	//
	// See Figure 2.1 in https://www.intel.com/content/dam/www/public/us/en/documents/guides/fit-bios-specification.pdf
	//
	// Note: A firmware image grows towards lower addresses. So an image will be mapped to addresses:
	//       [ BasePhysAddr-length .. BasePhysAddr )
	//
	// Note: SPI chip is mapped into this region. So we actually work directly with data of the SPI chip
	//
	// See also CalculatePhysAddrOfOffset().
	BasePhysAddr = 1 << 32 // "4GB"
)
