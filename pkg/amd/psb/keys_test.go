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
	// KeyID of the signing key for SMU off chip (0x08, 0x12) firmware and MP5 firmware (0x2A)
	smuSigningKeyID = buf16B{0x6e, 0x97, 0xee, 0xe0, 0x86, 0xbd, 0x4b, 0x41, 0xb5, 0x82, 0x01, 0xce, 0x9f, 0xe3, 0x08, 0x73}
	// KeyID of the signing key for PSP early secure unblock debug image
	earlySecurePSPKeyID = buf16B{0x80, 0xac, 0x38, 0xa7, 0x85, 0x99, 0x45, 0xf8, 0xba, 0x5f, 0xb9, 0xb4, 0xc7, 0xa5, 0x79, 0x8f}
	// KeyID of the signing key for security policy binary
	securityPolicyBinaryKeyID = buf16B{0xf2, 0x4b, 0x7f, 0x7e, 0xdc, 0xe5, 0x45, 0xdd, 0x89, 0xb6, 0x5c, 0xd0, 0x7e, 0xf7, 0x40, 0x97}
	// KeyID of the signing key for PSP AGESA Binary
	agesaKeyID = buf16B{0x28, 0x9a, 0xfe, 0x36, 0xf6, 0x3c, 0x4f, 0x88, 0xbc, 0x13, 0x85, 0xaa, 0x6d, 0x92, 0x38, 0x91}
	// KeyID of the signing key for SEV Code (0x39)
	sevCodeKeyID = buf16B{0x03, 0x11, 0x7b, 0x7e, 0x60, 0xcb, 0x40, 0x3e, 0xbf, 0x9e, 0xcd, 0x55, 0x7e, 0xcb, 0x99, 0x71}
	// KeyID of the signing key for DXIO PHY SRAM FW (0x42)
	dxioKeyID = buf16B{0xff, 0xfe, 0x23, 0x6b, 0x8b, 0xcc, 0x4a, 0x2b, 0xac, 0xbb, 0x85, 0x6e, 0x12, 0x03, 0x68, 0xfd}
	// KeyID of the signing key DRTM TA (0x47)
	drtmTaKeyID = buf16B{0x25, 0x59, 0xbe, 0x9e, 0x7b, 0xef, 0x4c, 0x54, 0x99, 0x02, 0x42, 0xc4, 0xfa, 0xe1, 0x55, 0x22}

	// Unknown keys (i.e. for which it is not clear what they sign)
	unknownKey1 = buf16B{0xea, 0x94, 0x0a, 0x66, 0x12, 0x38, 0x41, 0x2d, 0xb3, 0x9e, 0xab, 0xa2, 0x93, 0x4d, 0x4a, 0x9f}
)

type KeySuite struct {
	suite.Suite
}

func (suite *KeySuite) TestKeySetAddKey() {

	rootKey, err := NewRootKey(bytes.NewBuffer(amdRootKey))
	assert.NoError(suite.T(), err)

	keySet := NewKeySet()
	keySet.AddKey(rootKey, AMDRootKey)

	assert.Equal(suite.T(), 1, len(keySet.AllKeyIDs()))
	assert.NotNil(suite.T(), keySet.GetKey(KeyID(rootKeyID)))

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

func (suite *KeySuite) TestKeyDBParsing() {

	keySet := NewKeySet()
	err := parseKeyDatabase(keyDB, keySet)
	assert.NoError(suite.T(), err)

	assert.Equal(suite.T(), 7, len(keySet.AllKeyIDs()))

	// assert presence of all known keys
	assert.NotNil(suite.T(), keySet.GetKey(KeyID(securityPolicyBinaryKeyID)))
	assert.NotNil(suite.T(), keySet.GetKey(KeyID(sevCodeKeyID)))
	assert.NotNil(suite.T(), keySet.GetKey(KeyID(smuSigningKeyID)))
	assert.NotNil(suite.T(), keySet.GetKey(KeyID(earlySecurePSPKeyID)))
	assert.NotNil(suite.T(), keySet.GetKey(KeyID(unknownKey1)))
	assert.NotNil(suite.T(), keySet.GetKey(KeyID(dxioKeyID)))
	assert.NotNil(suite.T(), keySet.GetKey(KeyID(drtmTaKeyID)))

	// assert absence of keys which are not included in the key database
	assert.Nil(suite.T(), keySet.GetKey(KeyID(oemKeyID)))
	assert.Nil(suite.T(), keySet.GetKey(KeyID(agesaKeyID)))

}

func TestKeySuite(t *testing.T) {
	suite.Run(t, new(KeySuite))
}
