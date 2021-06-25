package manifest

// Firmware is an abstraction of a firmware image, obtained for example via flashrom
type Firmware interface {
	ImageBytes() []byte
	PhysAddrToOffset(physAddr uint64) uint64
	OffsetToPhysAddr(offset uint64) uint64
}
