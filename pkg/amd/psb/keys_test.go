package psb

import (
	"bytes"
	"crypto/sha256"

	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// SHA256 of the common RSA exponent, 0x10001
var (
	rsaCommonExponentSHA256 = [32]uint8{0xc8, 0xa2, 0x22, 0xa2, 0x60, 0xf3, 0x57, 0xf5, 0xfd, 0x2b, 0x6d, 0x22, 0x49, 0x2, 0x2e, 0xef, 0xea, 0xa2, 0x8, 0xbd, 0x12, 0x13, 0x7, 0x89, 0xa2, 0x60, 0x0, 0x9b, 0x6a, 0xea, 0x58, 0xbb}
	// Key ID of the root key belonging to AMD
	rootKeyID = buf16B{0x94, 0xc3, 0x8e, 0x41, 0x77, 0xd0, 0x47, 0x92, 0x92, 0xa7, 0xae, 0x67, 0x1d, 0x08, 0x3f, 0xb6}
	// KeyID of the OEM signing key
	oemKeyID = buf16B{0xef, 0x99, 0x1d, 0xb4, 0x41, 0x42, 0x44, 0x67, 0x92, 0x65, 0x92, 0x3d, 0xe8, 0xbc, 0x51, 0xd8}
)

// Signed Token of AMD root key (entry type 0x00 in PSP Directory Table), extracted from PSB-enabled
// firmware F09C_2B06.sign for Northdome Milan - Quanta platform.
var amdRootKey = []byte{
	0x01, 0x00, 0x00, 0x00, 0x94, 0xc3, 0x8e, 0x41, 0x77, 0xd0, 0x47, 0x92, 0x92, 0xa7, 0xae, 0x67,
	0x1d, 0x08, 0x3f, 0xb6, 0x94, 0xc3, 0x8e, 0x41, 0x77, 0xd0, 0x47, 0x92, 0x92, 0xa7, 0xae, 0x67,
	0x1d, 0x08, 0x3f, 0xb6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xab, 0x65, 0x45, 0x12, 0x5a, 0x63, 0x5d, 0x86, 0xdf, 0x23, 0x0b, 0xf4, 0x41, 0x6e, 0xdf, 0xf1,
	0x40, 0xe8, 0xb5, 0x20, 0x7f, 0x72, 0x7a, 0xef, 0x72, 0xc3, 0x14, 0x0c, 0x99, 0xe5, 0x83, 0x75,
	0xc7, 0xb3, 0xfb, 0xa6, 0x70, 0x79, 0xed, 0x5c, 0x64, 0xd1, 0x4b, 0x01, 0xd6, 0xc9, 0x4f, 0x8c,
	0x53, 0xd2, 0xf5, 0x7c, 0x7c, 0x7c, 0xcd, 0xf4, 0xe8, 0xe2, 0xda, 0xad, 0xd8, 0x30, 0xa8, 0x20,
	0xa4, 0xa0, 0xe3, 0xef, 0xaa, 0x90, 0xbe, 0x42, 0x8c, 0x3d, 0x9b, 0x31, 0xb6, 0x78, 0xa4, 0xd6,
	0xaa, 0xc6, 0xa8, 0x68, 0xe9, 0xc3, 0x1c, 0x69, 0xb0, 0x9e, 0x31, 0xbb, 0x72, 0x4b, 0x05, 0xcc,
	0x4d, 0xc3, 0x9f, 0x31, 0x79, 0x50, 0x93, 0xd1, 0x2b, 0x1e, 0xc2, 0xf7, 0xed, 0xd2, 0x48, 0x9e,
	0xcf, 0xea, 0x09, 0x7e, 0x49, 0x7a, 0xda, 0x9b, 0x24, 0x23, 0x61, 0xdc, 0x78, 0x3d, 0x43, 0x67,
	0x33, 0xfc, 0xac, 0xcf, 0x45, 0x2e, 0x5b, 0x86, 0xac, 0x62, 0x4b, 0x17, 0xb4, 0x00, 0x93, 0xe6,
	0x27, 0x80, 0xfe, 0x2d, 0x42, 0xe2, 0x9b, 0xb7, 0xe4, 0x9d, 0x43, 0x77, 0x73, 0xaa, 0x50, 0x32,
	0xf5, 0x95, 0xad, 0xbd, 0x6b, 0x1c, 0x90, 0x5e, 0xec, 0xad, 0x5c, 0xcc, 0x13, 0xe6, 0x7a, 0x62,
	0x89, 0x68, 0x2c, 0xbb, 0x8f, 0xf1, 0x38, 0xf3, 0x62, 0x60, 0x13, 0x21, 0xf3, 0xc9, 0x86, 0x4f,
	0xe5, 0x92, 0x43, 0x05, 0xfa, 0xec, 0x0a, 0x41, 0x1b, 0x47, 0xd5, 0xb1, 0x45, 0x34, 0x44, 0x79,
	0x82, 0x64, 0x70, 0xb8, 0xac, 0x2b, 0x9e, 0x52, 0xfc, 0xff, 0x03, 0x29, 0x07, 0xac, 0xf9, 0x22,
	0x5b, 0x33, 0x72, 0xcf, 0xc5, 0x44, 0x6c, 0xc9, 0x60, 0x13, 0x87, 0x28, 0xf2, 0xed, 0x9b, 0xe5,
	0x6d, 0x6a, 0x1e, 0xa0, 0x6c, 0xa0, 0x03, 0xcc, 0xc4, 0xc4, 0x92, 0xe3, 0x7e, 0xc5, 0x0a, 0x2f,
	0xff, 0x9d, 0xa1, 0xa6, 0xd7, 0xb7, 0x03, 0x7b, 0x3f, 0x8c, 0x27, 0xe3, 0xdf, 0xb1, 0x7a, 0x3d,
	0x48, 0xfd, 0x87, 0x1d, 0x4a, 0x87, 0xe9, 0xc2, 0x65, 0xe9, 0x5b, 0xcd, 0x6e, 0xb8, 0xb4, 0xa2,
	0xf3, 0x4f, 0x34, 0x62, 0x82, 0x39, 0x0d, 0xa2, 0x5c, 0x0b, 0x26, 0xe6, 0xd5, 0xe7, 0xcf, 0x85,
	0x15, 0xca, 0xed, 0xee, 0x51, 0x05, 0x65, 0x80, 0xdb, 0x3e, 0x9a, 0x5e, 0x68, 0x3f, 0xa8, 0x2a,
	0x64, 0x2e, 0xd9, 0xe2, 0x07, 0xaa, 0xbc, 0xb8, 0x7a, 0x0c, 0xfe, 0x38, 0xae, 0x57, 0x2c, 0x3d,
	0x36, 0xee, 0x77, 0x47, 0xeb, 0xb4, 0xc0, 0x8e, 0xaf, 0xef, 0xf8, 0x81, 0x6d, 0xe6, 0xb3, 0xd6,
	0xd8, 0x39, 0xe2, 0x1d, 0x46, 0x17, 0x39, 0x6b, 0xde, 0x4b, 0x8e, 0x9a, 0x32, 0x7c, 0x3f, 0xee,
	0x4f, 0x4d, 0x73, 0xd4, 0x8b, 0x5f, 0x52, 0x72, 0x3d, 0xee, 0x3a, 0x50, 0x26, 0x26, 0xab, 0x61,
	0x80, 0x27, 0x6a, 0x3c, 0x4b, 0xb6, 0xb1, 0x52, 0x43, 0xdc, 0xe9, 0xfe, 0xdd, 0x5f, 0xbc, 0x3b,
	0xd6, 0x52, 0xad, 0x37, 0x47, 0x39, 0xf2, 0x04, 0x87, 0x44, 0x73, 0xff, 0x57, 0x38, 0xf7, 0x6d,
	0x91, 0xf1, 0x29, 0x7e, 0x3e, 0x5d, 0xe6, 0x4e, 0xaa, 0xac, 0xd8, 0x73, 0x58, 0xc7, 0x8a, 0xcd,
	0xcc, 0xd2, 0xc0, 0x44, 0xd6, 0x5a, 0x5b, 0x34, 0xac, 0x47, 0xd4, 0x94, 0xa8, 0x90, 0x6d, 0x5e,
	0xd1, 0xd4, 0xc7, 0xd4, 0xf1, 0x28, 0xbf, 0x5f, 0x72, 0xb2, 0x18, 0xe6, 0x6d, 0x71, 0x23, 0x25,
	0xe0, 0x5b, 0x46, 0xc7, 0xd0, 0xbb, 0x42, 0x3f, 0x2f, 0xa1, 0x49, 0x49, 0x21, 0x71, 0xd4, 0xf3,
	0xd5, 0x63, 0x57, 0x8d, 0x5b, 0x60, 0xf3, 0xd5, 0x17, 0x6c, 0xb5, 0xa8, 0xdb, 0x92, 0xc5, 0x3e,
	0x98, 0x15, 0xdb, 0x25, 0xb6, 0xa2, 0x96, 0x89, 0xe8, 0x75, 0x4e, 0x12, 0xd9, 0x79, 0xb7, 0xd0,
}

// Signed Token of OEM signing key (entry type 0x05 in BSIO Directory Table), extracted from PSB-enabled
// firmware F09C_2B06.sign for Northdome Milan - Quanta platform.
var oemSigningKey = []byte{
	0x01, 0x00, 0x00, 0x00, 0xef, 0x99, 0x1d, 0xb4, 0x41, 0x42, 0x44, 0x67, 0x92, 0x65, 0x92, 0x3d,
	0xe8, 0xbc, 0x51, 0xd8, 0x94, 0xc3, 0x8e, 0x41, 0x77, 0xd0, 0x47, 0x92, 0x92, 0xa7, 0xae, 0x67,
	0x1d, 0x08, 0x3f, 0xb6, 0x08, 0x00, 0x00, 0x00, 0x8d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x1b, 0x91, 0x26, 0xfe, 0xc7, 0xb7, 0xdd, 0xc2, 0xfe, 0x1c, 0xde, 0xc7, 0xe0, 0x4a, 0x35, 0x9d,
	0xe8, 0x68, 0x24, 0x19, 0x2c, 0x05, 0xcd, 0x71, 0xda, 0xbe, 0xbd, 0xeb, 0xf5, 0x67, 0x73, 0xbe,
	0xfc, 0xb3, 0x03, 0x02, 0x92, 0xe5, 0x9c, 0x3c, 0xdd, 0x81, 0x0d, 0x80, 0xe8, 0x3e, 0x24, 0xd8,
	0x92, 0x30, 0x97, 0x98, 0x88, 0x64, 0xd8, 0x60, 0xa4, 0x02, 0x22, 0xc7, 0x89, 0x75, 0x19, 0x26,
	0xc1, 0x8d, 0xa1, 0x6b, 0xa6, 0xac, 0x8f, 0xe5, 0x40, 0x14, 0xc4, 0x06, 0xd0, 0x93, 0x23, 0x4f,
	0x98, 0xc5, 0xd3, 0x55, 0x42, 0x63, 0x37, 0x76, 0x5e, 0x8b, 0x9d, 0xf7, 0xcb, 0xa6, 0x39, 0xfd,
	0x17, 0x2a, 0x6c, 0xca, 0x40, 0xfc, 0x3d, 0xeb, 0x47, 0x46, 0x9e, 0x3a, 0x31, 0xbf, 0x4b, 0xfa,
	0x76, 0xfb, 0x8c, 0x02, 0x8c, 0x0a, 0xd6, 0x59, 0x62, 0x38, 0x96, 0x90, 0x33, 0x96, 0xf3, 0x76,
	0xf4, 0x4b, 0x8e, 0x2b, 0xf8, 0x9d, 0xb6, 0x49, 0x38, 0x1b, 0x4a, 0x4e, 0xe8, 0x2a, 0x09, 0xae,
	0xf2, 0x6e, 0xd0, 0x4e, 0x3e, 0x77, 0xad, 0x8a, 0x01, 0xc4, 0xbf, 0xd0, 0xdc, 0xd1, 0x46, 0xf1,
	0x66, 0x5f, 0xac, 0xb8, 0x1d, 0x71, 0x14, 0xfd, 0x4b, 0xdb, 0xfa, 0x7e, 0xd0, 0x2a, 0x8b, 0x8f,
	0x5b, 0xe7, 0x45, 0x81, 0xca, 0x01, 0x27, 0x6b, 0x0c, 0xaa, 0xbe, 0xfe, 0x45, 0x0a, 0xb8, 0x32,
	0x48, 0xe6, 0x91, 0x6b, 0xed, 0x51, 0x9a, 0x5b, 0x5b, 0xb0, 0x58, 0xe4, 0x91, 0x3e, 0x93, 0xf6,
	0x6d, 0x40, 0x8b, 0x52, 0x80, 0x07, 0x55, 0x67, 0x5d, 0x7b, 0xa3, 0xbf, 0x0b, 0x34, 0x92, 0x59,
	0x1c, 0x26, 0x55, 0xaf, 0x84, 0xc3, 0xb7, 0xf5, 0x1d, 0x12, 0xea, 0x32, 0x39, 0xc1, 0x34, 0x9a,
	0xb8, 0x14, 0x8a, 0xca, 0x7f, 0xc5, 0x5e, 0xb5, 0x6f, 0x1a, 0x57, 0xf1, 0x8d, 0x97, 0x78, 0x09,
	0xc1, 0x2a, 0x38, 0x5a, 0xf7, 0x6f, 0xd4, 0x73, 0x7c, 0xb8, 0x6f, 0x41, 0xb6, 0x85, 0xdd, 0x71,
	0x61, 0xe4, 0x42, 0xf5, 0xa9, 0x0b, 0x8c, 0x11, 0xaa, 0x9d, 0xa8, 0x28, 0x97, 0xce, 0xec, 0x89,
	0xac, 0x50, 0xe9, 0x58, 0x9c, 0x60, 0x77, 0x31, 0x81, 0x97, 0x8f, 0xa6, 0xeb, 0x30, 0x26, 0xd0,
	0x0c, 0xd5, 0x2b, 0x74, 0x40, 0xa9, 0x25, 0x41, 0x5d, 0x04, 0x68, 0xe3, 0xe4, 0x2c, 0x28, 0xa3,
	0xd5, 0xaf, 0x44, 0xc8, 0x3a, 0xc2, 0x2d, 0xad, 0x6b, 0x51, 0xd4, 0x19, 0x4b, 0x24, 0x2f, 0xdc,
	0x53, 0x32, 0xe0, 0x1f, 0x29, 0xf2, 0xe2, 0x20, 0x28, 0xa0, 0x99, 0xab, 0x64, 0x93, 0xd3, 0xad,
	0xcd, 0xda, 0xe3, 0x14, 0x0d, 0xa9, 0x96, 0x63, 0x7e, 0x37, 0xbd, 0xe2, 0x70, 0x3a, 0x88, 0xba,
	0x79, 0x10, 0x57, 0x6c, 0x92, 0xef, 0x90, 0xd4, 0x01, 0x0f, 0x2d, 0xe9, 0x46, 0x73, 0xcc, 0x68,
	0x12, 0x60, 0x0c, 0x84, 0x39, 0xdf, 0xd4, 0x25, 0x24, 0x13, 0xbf, 0xa9, 0xc2, 0xc2, 0xfb, 0x97,
	0x12, 0xcf, 0x0e, 0xd2, 0x99, 0x3a, 0x5e, 0xec, 0x13, 0x5d, 0x00, 0x44, 0x9c, 0xc1, 0x4d, 0xa0,
	0x7f, 0x01, 0x2c, 0x0b, 0xf9, 0x23, 0x6c, 0x8d, 0x4b, 0xe0, 0x90, 0xf8, 0xf6, 0xce, 0x2e, 0xbd,
	0x2b, 0x2a, 0x33, 0xf6, 0x58, 0x50, 0x80, 0x50, 0x54, 0x47, 0xa5, 0x1d, 0x21, 0xf3, 0x59, 0x81,
	0x61, 0xc8, 0xdb, 0x73, 0x3c, 0xa0, 0x13, 0x3b, 0xa7, 0x10, 0x3f, 0xa8, 0x5a, 0xb5, 0x27, 0x46,
	0x99, 0x12, 0xdb, 0x7d, 0x51, 0xe1, 0xbe, 0xbf, 0x47, 0xea, 0x43, 0x4e, 0xce, 0x25, 0x75, 0x06,
	0xb7, 0xab, 0x24, 0x23, 0xeb, 0xe8, 0xaf, 0xb3, 0x6c, 0xc4, 0x90, 0x07, 0x34, 0x28, 0xc9, 0xb7,
	0xe9, 0x39, 0x51, 0x74, 0xf8, 0xed, 0xaa, 0xb4, 0x62, 0x26, 0x55, 0xdf, 0x24, 0xfa, 0xbd, 0xac,
	0x89, 0x94, 0x59, 0x29, 0x55, 0xe9, 0x09, 0x66, 0xb2, 0xb0, 0x06, 0x2f, 0xd0, 0x90, 0xee, 0x9b,
	0xb4, 0xab, 0xe0, 0xb3, 0x6a, 0x29, 0x35, 0x0c, 0x45, 0x47, 0x88, 0xba, 0x3c, 0x81, 0x20, 0x59,
	0x8e, 0xd1, 0x07, 0x01, 0xc2, 0xc2, 0x54, 0x53, 0x6b, 0xac, 0xd1, 0x51, 0x1f, 0x23, 0xd2, 0xe6,
	0xba, 0x7b, 0x5d, 0xad, 0xb8, 0x49, 0x48, 0x41, 0x0f, 0x5a, 0x54, 0x02, 0x78, 0x37, 0x2b, 0xa2,
	0x67, 0xc9, 0xc8, 0x71, 0x83, 0xd7, 0x97, 0xe7, 0x98, 0x4a, 0x10, 0x93, 0xc7, 0xed, 0x66, 0xb6,
	0x9f, 0x6d, 0x78, 0xf6, 0x71, 0xc0, 0xa9, 0x51, 0x17, 0xbd, 0x03, 0x7c, 0xf0, 0x24, 0x84, 0xc0,
	0x69, 0x95, 0x6a, 0x07, 0xde, 0x22, 0xea, 0x8c, 0xe5, 0xc3, 0x2c, 0x5a, 0x19, 0xd1, 0xd6, 0x7c,
	0xe1, 0x51, 0xcd, 0xaa, 0xee, 0x57, 0x6e, 0x9e, 0x95, 0x22, 0x8b, 0x68, 0x27, 0xac, 0xdd, 0x64,
	0xe1, 0xa4, 0xb7, 0xd5, 0xbe, 0xd8, 0x99, 0xb9, 0xcf, 0xd9, 0xbf, 0x23, 0x55, 0x98, 0x7d, 0x09,
	0x4c, 0xac, 0x34, 0x30, 0x85, 0x5f, 0x63, 0x51, 0xdc, 0xb1, 0x0c, 0x54, 0x73, 0x66, 0x75, 0xde,
	0xed, 0x8c, 0x92, 0x2f, 0xe3, 0x3b, 0xe6, 0xcf, 0x1a, 0x39, 0x01, 0xb9, 0x47, 0x60, 0x3d, 0xdc,
	0x56, 0x3e, 0x80, 0xcd, 0xc0, 0x62, 0x52, 0xf0, 0x3b, 0x95, 0x64, 0x2a, 0xc5, 0x79, 0x3c, 0x8a,
	0xbd, 0x50, 0x85, 0x6e, 0x37, 0xca, 0x49, 0xe1, 0xcc, 0xd2, 0xfe, 0x80, 0xcd, 0x85, 0xbe, 0x32,
	0xa0, 0x6a, 0x39, 0xc1, 0x3a, 0x88, 0xcb, 0xf7, 0xc6, 0xb2, 0x80, 0x8b, 0xeb, 0xdb, 0x7a, 0xdb,
	0x67, 0x73, 0x20, 0xe4, 0x2e, 0x4d, 0xb1, 0x0d, 0xf6, 0x07, 0x17, 0x56, 0xfa, 0xd6, 0xf4, 0xe0,
	0x1c, 0x43, 0x80, 0x98, 0x57, 0x8f, 0xd0, 0x96, 0xce, 0x58, 0x9a, 0x60, 0xc3, 0xdd, 0x29, 0xfb,
	0xf5, 0x09, 0x24, 0x7d, 0xf2, 0x5d, 0x34, 0x4f, 0x5a, 0x76, 0x31, 0x6b, 0xd3, 0x2e, 0x36, 0x52,
	0x23, 0x55, 0x2d, 0x05, 0x43, 0x51, 0x5e, 0x6e, 0x85, 0x53, 0x77, 0x16, 0xdf, 0xe2, 0x44, 0x31,
	0x86, 0xe1, 0x52, 0x92, 0x48, 0x35, 0x6f, 0x4d, 0xb7, 0x0f, 0xc5, 0xcb, 0x49, 0x1b, 0x24, 0xa9,
	0xce, 0xc3, 0x26, 0xc4, 0xf0, 0x54, 0xc0, 0x8b, 0x5f, 0xfe, 0x75, 0xed, 0x9f, 0x51, 0x25, 0x0f,
	0x0c, 0xb2, 0x67, 0x60, 0x9c, 0x6d, 0x1d, 0x10, 0xed, 0xcc, 0xcc, 0x60, 0x09, 0xcc, 0x75, 0x8d,
	0x95, 0xbd, 0xa5, 0xc8, 0x15, 0xcf, 0xcf, 0x43, 0x8c, 0x40, 0x06, 0x18, 0x2d, 0x81, 0x66, 0xde,
	0xbe, 0xeb, 0xf1, 0x4f, 0x01, 0xb0, 0x6e, 0xf2, 0x55, 0x2c, 0x60, 0xdf, 0xa0, 0x73, 0x6e, 0x55,
	0xe1, 0x87, 0x00, 0xbc, 0xad, 0x89, 0x31, 0xa2, 0xf3, 0x96, 0x39, 0xaf, 0x17, 0x03, 0xb6, 0xa2,
	0x06, 0xf7, 0xe9, 0x0c, 0x63, 0x59, 0x80, 0x3e, 0xe2, 0x67, 0x25, 0x76, 0x13, 0x22, 0xe8, 0x40,
	0x51, 0x0a, 0xad, 0x31, 0xe5, 0x0c, 0xaf, 0x71, 0xa3, 0x36, 0xe7, 0x20, 0xfc, 0x61, 0xd4, 0x79,
	0x96, 0x9e, 0x02, 0x10, 0x50, 0xa0, 0x1e, 0x13, 0x4e, 0xf3, 0xe2, 0x3b, 0x7d, 0x9d, 0xba, 0x2b,
	0xdd, 0xea, 0x54, 0xce, 0x18, 0x49, 0x85, 0x36, 0x8a, 0x9b, 0xed, 0xbb, 0x9b, 0xe9, 0x64, 0x9c,
	0x19, 0x7f, 0x7d, 0xec, 0xd6, 0x9a, 0x14, 0x79, 0x72, 0x77, 0x5f, 0xff, 0xde, 0xec, 0x10, 0x53,
	0x99, 0x23, 0x64, 0xeb, 0x5b, 0x01, 0xcb, 0x5f, 0x6b, 0x17, 0xde, 0x8e, 0x6b, 0x06, 0x69, 0x56,
	0xfa, 0x0c, 0x4e, 0xf0, 0x71, 0x09, 0xb0, 0xc5, 0x8e, 0xcb, 0xdc, 0x9b, 0x35, 0x5e, 0x1f, 0xd8,
	0xc4, 0xed, 0x4e, 0xb4, 0xf4, 0x52, 0x64, 0x0a, 0x03, 0xa3, 0xa9, 0x7b, 0x4f, 0x2c, 0x17, 0x55,
}

type KeySuite struct {
	suite.Suite
}

func (suite *KeySuite) TestRootKeyFields() {
	key, err := NewRootKey(bytes.NewBuffer(amdRootKey))
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), uint32(0x01), key.versionID)

	assert.Equal(suite.T(), KeyID(rootKeyID), key.keyID)
	assert.Equal(suite.T(), rootKeyID, key.certifyingKeyID)
	assert.Equal(suite.T(), uint32(0x00), key.keyUsageFlag)

	assert.Equal(suite.T(), uint32(0x1000), key.exponentSize)
	assert.Equal(suite.T(), uint32(0x1000), key.modulusSize)

	hashExponent := sha256.Sum256(key.exponent)
	hashModulus := sha256.Sum256(key.modulus)

	expectedModulusHash := [32]uint8{0x87, 0xdb, 0xd4, 0x5, 0x40, 0x23, 0x7d, 0xf3, 0x9c, 0x7, 0x2e, 0xfc, 0x2b, 0xa9, 0x1e, 0xc2, 0x3a, 0xe, 0xe5, 0x7e, 0x2a, 0xf0, 0x74, 0xdd, 0xe8, 0x44, 0xa4, 0x61, 0x4d, 0xc4, 0x57, 0x7b}

	assert.Equal(suite.T(), rsaCommonExponentSHA256, hashExponent)
	assert.Equal(suite.T(), expectedModulusHash, hashModulus)

}

func (suite *KeySuite) TestOEMKeyFields() {

	rootKey, err := NewRootKey(bytes.NewBuffer(amdRootKey))
	assert.NoError(suite.T(), err)

	// parse root key and use it to validate token key
	keySet := NewKeySet()
	keySet.AddKey(rootKey, AMDRootKey)

	key, err := NewTokenKey(bytes.NewBuffer(oemSigningKey), keySet)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), uint32(0x01), key.versionID)

	assert.Equal(suite.T(), KeyID(oemKeyID), key.keyID)
	assert.Equal(suite.T(), rootKey.keyID, KeyID(key.certifyingKeyID))

	assert.Equal(suite.T(), uint32(0x08), key.keyUsageFlag)

	assert.Equal(suite.T(), uint32(0x1000), key.exponentSize)
	assert.Equal(suite.T(), uint32(0x1000), key.modulusSize)

	hashExponent := sha256.Sum256(key.exponent)
	hashModulus := sha256.Sum256(key.modulus)

	expectedModulusHash := [32]uint8{0x53, 0xbf, 0x68, 0xb9, 0x67, 0x97, 0xc5, 0x1f, 0xdd, 0xd3, 0xe6, 0x65, 0x2b, 0x2d, 0xdd, 0x2c, 0x6e, 0x57, 0x37, 0xee, 0x69, 0x6c, 0x50, 0x83, 0xa1, 0x25, 0xa9, 0x74, 0x24, 0xc1, 0xaf, 0x91}

	assert.Equal(suite.T(), rsaCommonExponentSHA256, hashExponent)
	assert.Equal(suite.T(), expectedModulusHash, hashModulus)

}

func TestKeySuite(t *testing.T) {
	suite.Run(t, new(KeySuite))
}
