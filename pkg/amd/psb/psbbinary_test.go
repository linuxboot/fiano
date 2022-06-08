package psb

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/klauspost/compress/zstd"

	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// SMU off chip firmware signing key information
var N = "971472917905694235859527690907502923402301948031921241171273698806712501341143764872164817936205323093673268936716169271014956780829744939605805336378355604317689589643879933296619769853977997537504409513857548495835554760316169706145871580241299859391727532123062316131763291333497897666085493912196453830838835409116482525805019707393297818644968410993413227674593522445365251216146843534545538446317137254095278019564256619548518070446087126473960778214502148894932879929259282158773739433517309889480032232186219446391610435919379779378252560032397509979809202392043110002380553502817271070140095904800150060054898411959116413989750574319580379588063907374731560190664369153626299598002608484164204182073967364520170387618360414494928968064669008506200599321614764379343663974785424808230448954042498800415697272404985468748776993396194504501173460207698442122815473122167399338113883863561341937240713815386295760840924504030444583243381824402019007306020777513381800531855947355754646526659806863711949295870720607069380951550984974668335178048036250641301510976999844724811954772642716092471925323531085871838421575832526959241303117218657087055880924069551198635498158413029865582648473844773084423426422930595846516126856911"
var expectedSmuOffChipFirmwareHash = [32]byte{
	0xd8, 0xdc, 0x03, 0xff, 0x18, 0x1a, 0xcc, 0x9d, 0x09, 0xac, 0x5a, 0xe7, 0x59, 0x67, 0xdc, 0x96,
	0x60, 0xe7, 0xbb, 0x08, 0xd0, 0x3f, 0xa3, 0xb1, 0xbf, 0x64, 0x17, 0x0e, 0x43, 0xdc, 0xb2, 0xf2,
}
var expectedZeroSmuOffChipFirmwareHash = [32]byte{
	0x10, 0xe2, 0x10, 0x3e, 0xe7, 0x39, 0x21, 0x93, 0x1a, 0x78, 0x28, 0xeb, 0xdf, 0x32, 0x5d, 0x3a,
	0x3a, 0x64, 0xc7, 0xa9, 0x0c, 0xc1, 0xda, 0x5c, 0x0c, 0xa6, 0xfe, 0x17, 0xb1, 0xe3, 0xdd, 0x78,
}

const FirmwareLen = 16777216

type PsbBinarySuite struct {
	suite.Suite

	firmwareImage []byte
}

func (suite *PsbBinarySuite) SetupTest() {
	suite.firmwareImage = make([]byte, 0)
	reader, err := zstd.NewReader(nil)
	if err != nil {
		panic("could not create zstd reader")
	}
	suite.firmwareImage, err = reader.DecodeAll(firmwareImageCompressed, nil)
	if err != nil {
		panic("could not decompress zstd firmware")
	}
}

func (suite *PsbBinarySuite) TestPSBBinaryIsParsedCorrectly() {
	psbBinary, err := newPSPBinary(smuOffChipFirmware)
	require.NoError(suite.T(), err)

	hdr := psbBinary.Header()
	require.Equal(suite.T(), uint32(0x31535024), hdr.Version())
}

func (suite *PsbBinarySuite) TestPSBBinarySignedData() {
	// we are using SMU off-chip firmware for testing PSB binary control
	// paths and we need the corresponding signing key, which is contained
	// in the key database. We could just extract the single key from the
	// database, but it's easier to parse the database as a whole
	keySet := NewKeySet()
	err := parseKeyDatabase(keyDB, keySet)
	require.NoError(suite.T(), err)

	psbBinary, err := newPSPBinary(smuOffChipFirmware)
	require.NoError(suite.T(), err)

	blob, err := psbBinary.getSignedBlob(keySet)

	require.NoError(suite.T(), err)

	// verify that the signed data matches the content of the blob, excluding the final signature
	require.Equal(suite.T(), smuOffChipFirmware[:len(smuOffChipFirmware)-512], blob.SignedData())

	sig := blob.Signature()
	require.NotNil(suite.T(), sig)
	key := sig.SigningKey()
	require.NotNil(suite.T(), key)
	require.Equal(suite.T(), hex.EncodeToString(smuSigningKeyID[:]), key.data.KeyID.String())

	// obtain the RSA key from the generic Key object
	pubKey, err := key.Get()
	require.NoError(suite.T(), err)
	rsaKey := pubKey.(*rsa.PublicKey)
	require.NotNil(suite.T(), rsaKey)

	n := big.Int{}
	n.SetString(N, 10)
	require.Equal(suite.T(), n, *rsaKey.N)
	require.Equal(suite.T(), int(65537), rsaKey.E)
}

func (suite *PsbBinarySuite) TestPSBBinaryPSPDirectoryLevel2Entry() {
	// Test full extraction from firmware of entry from PSP Directory
	require.Equal(suite.T(), FirmwareLen, len(suite.firmwareImage))

	amdFw, err := ParseAMDFirmware(suite.firmwareImage)
	require.NoError(suite.T(), err)

	smuOffChipFirmwareType := amd_manifest.PSPDirectoryTableEntryType(0x12)

	data, err := ExtractPSPEntry(amdFw, 2, smuOffChipFirmwareType)
	require.NoError(suite.T(), err)
	shaSmuOffChipFirmwareHash := sha256.Sum256(data)

	require.Equal(suite.T(), expectedSmuOffChipFirmwareHash, shaSmuOffChipFirmwareHash)

	// if we dump the SMU off-chip firmware level 1 entry, we expect to find a region of all zeros
	data, err = ExtractPSPEntry(amdFw, 1, smuOffChipFirmwareType)
	require.NoError(suite.T(), err)
	shaSmuOffChipFirmwareHash = sha256.Sum256(data)

	require.Equal(suite.T(), expectedZeroSmuOffChipFirmwareHash, shaSmuOffChipFirmwareHash)
}

func (suite *PsbBinarySuite) TestPSBBinaryPSPDirectoryLevel2EntryValidation() {
	// Test positive validation of PSP Directory entry
	require.Equal(suite.T(), FirmwareLen, len(suite.firmwareImage))

	amdFw, err := ParseAMDFirmware(suite.firmwareImage)
	require.NoError(suite.T(), err)

	keyDB, err := GetKeys(amdFw, 2)
	require.NoError(suite.T(), err)

	signatureValidation, err := ValidatePSPEntries(amdFw, keyDB, PSPDirectoryLevel2, []uint32{0x12})

	require.NoError(suite.T(), err)
	require.Equal(suite.T(), 1, len(signatureValidation))
	require.NoError(suite.T(), signatureValidation[0].err)
	require.NotNil(suite.T(), signatureValidation[0].signingKey)

	signingKey := signatureValidation[0].signingKey

	require.Equal(suite.T(), hex.EncodeToString(smuSigningKeyID[:]), signingKey.data.KeyID.String())
}

func (suite *PsbBinarySuite) TestPSBBinaryPSPDirectoryLevel2EntryWrongSignature() {
	// Test negative validation of PSP Directory entry after corruption
	require.Equal(suite.T(), FirmwareLen, len(suite.firmwareImage))

	amdFw, err := ParseAMDFirmware(suite.firmwareImage)
	require.NoError(suite.T(), err)

	smuOffChipFirmwareType := 0x12

	// obtain the ranges of entry 0x12 within PSP Directory Level 2 (SMU off-chip firmware)
	// and corrupt the very beginning of the blob
	pspFirmware := amdFw.PSPFirmware()
	for _, entry := range pspFirmware.PSPDirectoryLevel2.Entries {
		if entry.Type == amd_manifest.PSPDirectoryTableEntryType(smuOffChipFirmwareType) {
			amdFw.Firmware().ImageBytes()[entry.LocationOrValue] = 0x0
		}
	}

	keyDB, err := GetKeys(amdFw, 2)
	require.NoError(suite.T(), err)

	// ValidatePSPEntries will succeed, but the signature validation object returned will hold a signature check error
	signatureValidation, err := ValidatePSPEntries(amdFw, keyDB, PSPDirectoryLevel2, []uint32{uint32(smuOffChipFirmwareType)})
	require.NoError(suite.T(), err)

	require.Equal(suite.T(), 1, len(signatureValidation))
	require.Error(suite.T(), signatureValidation[0].err)
	var sigErr *SignatureCheckError
	require.True(suite.T(), errors.As(signatureValidation[0].err, &sigErr))

	require.NotNil(suite.T(), signatureValidation[0].signingKey)
	signingKey := signatureValidation[0].signingKey
	require.Equal(suite.T(), hex.EncodeToString(smuSigningKeyID[:]), signingKey.data.KeyID.String())
}

func (suite *PsbBinarySuite) TestPSBBinaryPSPDirectoryLevel2EntryWrongKeys() {
	// Test negative validation of PSP Directory entry after corruption
	require.Equal(suite.T(), FirmwareLen, len(suite.firmwareImage))

	amdFw, err := ParseAMDFirmware(suite.firmwareImage)
	require.NoError(suite.T(), err)

	smuOffChipFirmwareType := 0x12

	// signatureParameters indicates the id of the signing key and is placed at 56 bytes offset
	// from the beginning of the blob
	signatureParametersOffset := uint64(56)

	// obtain the ranges of entry 0x12 within PSP Directory Level 2 (SMU off-chip firmware)
	// and modify the fingerprint of the signing key for the blob so that the key becomes
	// effectively unknown
	pspFirmware := amdFw.PSPFirmware()
	for _, entry := range pspFirmware.PSPDirectoryLevel2.Entries {
		if entry.Type == amd_manifest.PSPDirectoryTableEntryType(smuOffChipFirmwareType) {
			amdFw.Firmware().ImageBytes()[entry.LocationOrValue+signatureParametersOffset] = 0x99
		}
	}

	keyDB, err := GetKeys(amdFw, 2)
	require.NoError(suite.T(), err)

	// ValidatePSPEntries will succeed, but the signature validation object returned will hold a signature check error
	signatureValidation, err := ValidatePSPEntries(amdFw, keyDB, PSPDirectoryLevel2, []uint32{uint32(smuOffChipFirmwareType)})
	require.NoError(suite.T(), err)

	require.Equal(suite.T(), 1, len(signatureValidation))
	require.Error(suite.T(), signatureValidation[0].err)

	var unknownSigningKeyErr *UnknownSigningKeyError
	require.True(suite.T(), errors.As(signatureValidation[0].err, &unknownSigningKeyErr))
}

func (suite *PsbBinarySuite) TestPSBBinaryDumpEntry() {
	require.Equal(suite.T(), FirmwareLen, len(suite.firmwareImage))

	amdFw, err := ParseAMDFirmware(suite.firmwareImage)
	require.NoError(suite.T(), err)

	var buff bytes.Buffer

	// dump SMU off-chip firmware
	smuOffChipFirmwareType := amd_manifest.PSPDirectoryTableEntryType(0x12)
	n, err := DumpPSPEntry(amdFw, 2, smuOffChipFirmwareType, &buff)

	require.NoError(suite.T(), err)
	require.Equal(suite.T(), n, len(smuOffChipFirmware))

	shaSmuOffChipFirmwareHash := sha256.Sum256(buff.Bytes())
	expectedSmuOffChipFirmwareHash := [32]byte{
		0xd8, 0xdc, 0x03, 0xff, 0x18, 0x1a, 0xcc, 0x9d, 0x09, 0xac, 0x5a, 0xe7, 0x59, 0x67, 0xdc, 0x96,
		0x60, 0xe7, 0xbb, 0x08, 0xd0, 0x3f, 0xa3, 0xb1, 0xbf, 0x64, 0x17, 0x0e, 0x43, 0xdc, 0xb2, 0xf2,
	}
	require.Equal(suite.T(), expectedSmuOffChipFirmwareHash, shaSmuOffChipFirmwareHash)

	// dump Key database
	keyDatabaseLen := 4992

	buff.Reset()
	n, err = DumpPSPEntry(amdFw, 2, KeyDatabaseEntry, &buff)

	require.NoError(suite.T(), err)
	require.Equal(suite.T(), n, keyDatabaseLen)

	keyDBHash := sha256.Sum256(buff.Bytes())

	expectedKeyDBHash := [32]byte{
		0xec, 0x16, 0x0f, 0xfa, 0x63, 0xae, 0xcd, 0xc9, 0x23, 0xb0, 0x34, 0x16, 0x70, 0x85, 0x50, 0xe7,
		0x49, 0x48, 0xba, 0x6c, 0xf7, 0x7f, 0x01, 0x49, 0x53, 0x1b, 0x2a, 0x6a, 0x66, 0x28, 0x2a, 0x2c,
	}

	require.Equal(suite.T(), expectedKeyDBHash, keyDBHash)
}

func (suite *PsbBinarySuite) TestPSBBinaryPatchEntry() {
	require.Equal(suite.T(), FirmwareLen, len(suite.firmwareImage))

	amdFw, err := ParseAMDFirmware(suite.firmwareImage)
	require.NoError(suite.T(), err)

	smuOffChipFirmwareType := amd_manifest.PSPDirectoryTableEntryType(0x12)
	patchedEntry := make([]byte, len(smuOffChipFirmware))
	buff := bytes.NewBuffer(patchedEntry)

	firmwareImageCopy := make([]byte, 0, len(suite.firmwareImage))
	buffImage := bytes.NewBuffer(firmwareImageCopy)

	n, err := PatchPSPEntry(amdFw, 2, smuOffChipFirmwareType, buff, buffImage)

	require.NoError(suite.T(), err)
	require.Equal(suite.T(), len(suite.firmwareImage), n)

	start := uint64(0)
	end := uint64(0)
	pspFirmware := amdFw.PSPFirmware()
	for _, entry := range pspFirmware.PSPDirectoryLevel2.Entries {
		if entry.Type == amd_manifest.PSPDirectoryTableEntryType(smuOffChipFirmwareType) {
			start = entry.LocationOrValue
			end = entry.LocationOrValue + uint64(entry.Size)
		}
	}

	require.NotEqual(suite.T(), 0, start)
	require.NotEqual(suite.T(), 0, end)

	require.Equal(suite.T(), sha256.Sum256(firmwareImageCopy[:start]), sha256.Sum256(suite.firmwareImage[:start]))

	require.Equal(suite.T(), expectedSmuOffChipFirmwareHash, sha256.Sum256(suite.firmwareImage[start:end]))
	require.Equal(suite.T(), expectedZeroSmuOffChipFirmwareHash, sha256.Sum256(buffImage.Bytes()[start:end]))

	require.Equal(suite.T(), sha256.Sum256(buffImage.Bytes()[end:]), sha256.Sum256(suite.firmwareImage[end:]))
}

func TestPsbBinarySuite(t *testing.T) {
	suite.Run(t, new(PsbBinarySuite))
}
