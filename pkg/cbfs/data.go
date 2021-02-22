// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

var (
	Master = []byte{
		/*0000*/ 0x5f, 0x5f, 0x46, 0x4d, 0x41, 0x50, 0x5f, 0x5f, 0x01, 0x01, 0x00, 0x00, 0xfc, 0xff, 0x00, 0x00, //|__FMAP__........|
		/*0010*/ 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x46, 0x4c, 0x41, 0x53, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, //|......FLASH.....|
		/*0020*/ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //|................|
		/*0030*/ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, //|................|
		/*0040*/ 0x42, 0x49, 0x4f, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //|BIOS............|
		/*0050*/ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //|................|
		/*0060*/ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x46, 0x4d, 0x41, 0x50, 0x00, 0x00, //|..........FMAP..|
		/*0070*/ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //|................|
		/*0080*/ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, //|................|
		/*0090*/ 0x00, 0xfe, 0x03, 0x00, 0x43, 0x4f, 0x52, 0x45, 0x42, 0x4f, 0x4f, 0x54, 0x00, 0x00, 0x00, 0x00, //|....COREBOOT....|
		/*00a0*/ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //|................|
		/*00b0*/ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*00c0*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*00d0*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*00e0*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*00f0*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*0100*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*0110*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*0120*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*0130*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*0140*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*0150*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*0160*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*0170*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*0180*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*0190*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*01a0*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*01b0*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*01c0*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*01d0*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*01e0*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*01f0*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*0200*/ 0x4c, 0x41, 0x52, 0x43, 0x48, 0x49, 0x56, 0x45, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x02, //|LARCHIVE... ....|
		/*0210*/ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x63, 0x62, 0x66, 0x73, 0x20, 0x6d, 0x61, 0x73, //|.......8cbfs mas|
		/*0220*/ 0x74, 0x65, 0x72, 0x20, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //|ter header......|
		/*0230*/ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4f, 0x52, 0x42, 0x43, 0x31, 0x31, 0x31, 0x32, //|........ORBC1112|
		/*0240*/ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x02, 0x00, //|...........@....|
		/*0250*/ 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*0260*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*0270*/ 0x4c, 0x41, 0x52, 0x43, 0x48, 0x49, 0x56, 0x45, 0x00, 0x00, 0x00, 0x20, 0xff, 0xff, 0xff, 0xff, //|LARCHIVE..w.....|
		/*0280*/ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //|.......(........|
		/*0290*/ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*02a0*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|
		/*02b0*/ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //|................|

	}
	ListOutput = `FMAP REGIOName: COREBOOT
Name                           Offset     Type           Size   Comp
cbfs master header             0x0        cbfs header        32 none
fallback/romstage              0x80       stage           15812 none
fallback/ramstage              0x3ec0     stage           52417 none
config                         0x10bc0    raw               355 none
revision                       0x10d80    raw               576 none
cmos_layout.bin                0x11000    cmos_layout       548 none
fallback/dsdt.aml              0x11280    raw              6952 none
fallback/payload               0x12e00    simple elf         28 none
(empty)                        0x12e80    null           183192 none
bootblock                      0x3fa40    bootblock         880 none
`
)