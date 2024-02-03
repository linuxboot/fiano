package consts

// CalculatePhysAddrFromTailOffset calculates the physical address (address to a
// region mapped from the SPI chip) using an offset towards down, relatively
// to BasePhysAddr.
//
// Examples:
//     CalculatePhysAddrFromTailOffset(0x01) ==  0xffffffff
//     CalculatePhysAddrFromTailOffset(0x40) ==  0xffffffc0
func CalculatePhysAddrFromTailOffset(offset uint64) uint64 {
	return BasePhysAddr - offset
}

// CalculateTailOffsetFromPhysAddr calculates the offset (towards down, relatively
// to BasePhysAddr) of the physical address (address to a region mapped from
// the SPI chip).
//
// This is the reverse function to CalculatePhysAddrFromTailOffset()
//
// Examples:
//     CalculateTailOffsetFromPhysAddr(0xffffffff) == 0x01
//     CalculateTailOffsetFromPhysAddr(0xffffffc0) == 0x40
func CalculateTailOffsetFromPhysAddr(physAddr uint64) uint64 {
	return BasePhysAddr - physAddr
}

// CalculateOffsetFromPhysAddr calculates the offset within an image
// of the physical address (address to a region mapped from
// the SPI chip).
//
// Examples:
//     CalculateOffsetFromPhysAddr(0xffffffff, 0x1000) == 0xfff
//     CalculateOffsetFromPhysAddr(0xffffffc0, 0x1000) == 0xfc0
func CalculateOffsetFromPhysAddr(physAddr uint64, imageSize uint64) uint64 {
	startAddr := BasePhysAddr - imageSize
	return physAddr - startAddr
}
