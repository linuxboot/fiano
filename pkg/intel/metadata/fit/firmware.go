package fit

// Firmware is an abstraction from (*uefi.UEFI).
type Firmware interface {
	ImageBytes() []byte
	PhysAddrToOffset(physAddr uint64) uint64
}
