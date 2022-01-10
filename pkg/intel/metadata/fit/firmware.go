// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

// Firmware is an abstraction from (*uefi.UEFI).
type Firmware interface {
	ImageBytes() []byte
	PhysAddrToOffset(physAddr uint64) uint64
}
