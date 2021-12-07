// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package manifest

const (
	biosDirectoryChecksumDataOffset = 8
	pspDirectoryChecksumDataOffset  = 8
)

// CalculateBiosDirectoryCheckSum calculates expected checksum of BIOS Directory represented in serialised form
func CalculateBiosDirectoryCheckSum(biosDirRaw []byte) uint32 {
	return fletcherCRC32(biosDirRaw[biosDirectoryChecksumDataOffset:])
}

// CalculatePSPDirectoryCheckSum calculates expected checksum of PSP Directory represented in serialised form
func CalculatePSPDirectoryCheckSum(pspDirRaw []byte) uint32 {
	return fletcherCRC32(pspDirRaw[pspDirectoryChecksumDataOffset:])
}

func fletcherCRC32(data []byte) uint32 {
	var c0, c1 uint32
	var i int
	l := (len(data) + 1) & ^1

	for l > 0 {
		blockLen := l
		if blockLen > 360*2 {
			blockLen = 360 * 2
		}
		l -= blockLen

		for {
			val := uint16(data[i])
			i++
			if i < len(data) {
				val += uint16(data[i]) << 8
				i++
			}
			c0 = c0 + uint32(val)
			c1 = c1 + c0
			blockLen -= 2
			if blockLen == 0 {
				break
			}
		}

		c0 = c0 % 65535
		c1 = c1 % 65535
	}
	return c1<<16 | c0
}
