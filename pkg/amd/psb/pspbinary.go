package psb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	amd_manifest "github.com/9elements/converged-security-suite/pkg/amd/manifest"
)

// pspHeaderSize represents the size of the header pre-pended to PSP binaries
const pspHeaderSize = 0x100

// signedDataStart indicates the start address of signed data content within a PSP binary
const signedDataStart = 0x0

// sizeSignedToSignatureParametersLen is the size of the header from sizeSigned field to signatureParameters
const sizeSignedToSignatureParametersLen = 32

// signatureParametersToSizeImageLen is the size of the header from signatureParameters field to sizeImage
const signatureParametersToSizeImageLen = 36

// PspHeader models the header pre-pended to PSP binaries
type PspHeader struct {
	nonce                 buf16B
	headerVersion         uint32
	sizeSigned            uint32
	encryptionOptions     uint32
	ikekType              uint8
	reserved0             buf3B
	encryptionParameters  buf16B
	signatureOption       uint32
	signatureAlgorithmID  uint32
	signatureParameters   buf16B
	compressionOptions    uint32
	securityPatchLevel    uint32
	uncompressedImageSize uint32
	compressedImageSize   uint32
	compressionParameters buf8B
	imageVersion          uint32
	apuFamilyID           uint32
	firmwareLoadAddress   uint32
	sizeImage             uint32
	sizeFwUnsigned        uint32
	firmwareSplitAddress  uint32
	reserved              buf4B
	fwType                uint8
	fwSubType             uint8
	reserved1             uint16
	encryptionKey         buf16B
	signingInfo           buf16B
	fwSpecificData        buf32B
	debugEncKey           buf16B

	// There should be 48 bytes of padding after the last field of the header,
	// which can be ignored. What we care about is the signature of the binary,
	// stored at the bottom of the image described by the header. This can be
	// looked up via sizeSigned and sizeImage

}

// Version returns the headerVersion field of the pspHeader structure
func (h *PspHeader) Version() uint32 {
	return h.headerVersion
}

// PSPBinary represents a generic PSPBinary with pre-pended header structure
type PSPBinary struct {

	// header of the binary
	header PspHeader

	// raw data of the whole PSP binary, including header. Signature includes
	// the header, keeping track of the whole raw content of the image allows
	// to easily build structures necessary for signature validation.
	raw []byte
}

// Header returns a pointer to the PspHeader structure of the binary. Fields of the PspHeader structure are not exported
func (b *PSPBinary) Header() *PspHeader {
	return &b.header
}

// GetSignature implements SignatureGetter interface for PSPBinary
func (b *PSPBinary) GetSignature() (*Signature, SignedData, error) {

	if b.header.sizeSigned == 0 {
		return nil, nil, fmt.Errorf("size of signed data cannot be 0 for PSPBinary")
	}
	if b.header.sizeImage == 0 {
		return nil, nil, fmt.Errorf("size of image cannot be 0 for PSPBinary")
	}

	if b.header.sizeSigned > b.header.sizeImage {
		return nil, nil, fmt.Errorf("size of signed image cannot be > size of image (%d > %d)", b.header.sizeSigned, b.header.sizeImage)
	}

	// TODO: for the moment, assume the signature is 512 bytes long (RSA4096).
	// GetSignature should be given in input the key database, so that
	// the fingerprint of the key which signed the header can be compared
	// with the known keys to decide the expected length of the signature.
	// We need full support for parsing key database before being able to
	// pass it to GetSignature().

	sizeSignature := uint32(512)
	signatureStart := b.header.sizeImage - sizeSignature
	signatureEnd := signatureStart + sizeSignature
	if err := checkBoundaries(uint64(signatureStart), uint64(signatureEnd), b.raw); err != nil {
		return nil, nil, fmt.Errorf("could not extract signature from raw PSPBinary: %w", err)
	}

	signedDataEnd := signedDataStart + b.header.sizeSigned + pspHeaderSize
	if err := checkBoundaries(uint64(signedDataStart), uint64(signedDataEnd), b.raw); err != nil {
		return nil, nil, fmt.Errorf("could not extract signed data from raw PSPBinary: %w", err)
	}

	var keyFingerprint strings.Builder
	fmt.Fprintf(&keyFingerprint, "%x", b.header.signatureParameters)

	signature := NewSignature(b.raw[signatureStart:signatureEnd], keyFingerprint.String())
	signedData, err := NewPspBinarySignedData(b.raw[signedDataStart:signedDataEnd])
	if err != nil {
		return nil, nil, fmt.Errorf("could not extract signed data from PSP binary")
	}

	return &signature, signedData, nil
}

// NewPSPBinary creates a PSPBinary object, with associated header
func NewPSPBinary(data []byte) (*PSPBinary, error) {

	pspBinary := PSPBinary{}
	pspBinary.raw = make([]byte, len(data), len(data))
	copied := copy(pspBinary.raw, data)
	if copied != len(data) {
		return nil, fmt.Errorf("expected %d copied data for raw PSP binary, got %d", len(data), copied)
	}

	buff := bytes.NewBuffer(pspBinary.raw)

	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header.nonce); err != nil {
		return nil, fmt.Errorf("could not parse nonce from PSPBinary: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header.headerVersion); err != nil {
		return nil, fmt.Errorf("could not parse header version from PSPBinary: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header.sizeSigned); err != nil {
		return nil, fmt.Errorf("could not parse sizeSigned from PSPBinary: %w", err)

	}

	// skip parsing up to signatureParameters, all other fields are not relevant at the moment
	unknown := make([]byte, sizeSignedToSignatureParametersLen)
	if err := binary.Read(buff, binary.LittleEndian, unknown); err != nil {
		return nil, fmt.Errorf("could not read header until sizeSignedToSignatureParametersLen: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header.signatureParameters); err != nil {
		return nil, fmt.Errorf("could not read header until sizeImage: %w", err)
	}

	// skip parsing up to sizeImage, all other fields are not relevant at the moment
	unknown = make([]byte, signatureParametersToSizeImageLen)
	if err := binary.Read(buff, binary.LittleEndian, unknown); err != nil {
		return nil, fmt.Errorf("could not read header until sizeImage: %w", err)
	}

	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header.sizeImage); err != nil {
		return nil, fmt.Errorf("could not read sizeImage: %w", err)
	}
	return &pspBinary, nil
}

// ExtractPSPBinary extracts entries from the PSP directory based on entry ID. The binary
// is supposed to have a header described by PspHeader structure. We assume to look-up for
// the entry in the level 1 directory.
func ExtractPSPBinary(id amd_manifest.PSPDirectoryTableEntryType, pspFw *amd_manifest.PSPFirmware, firmware amd_manifest.Firmware) (*PSPBinary, error) {

	if pspFw == nil {
		panic("cannot extract key database from nil PSP Firmware")
	}

	if pspFw.PSPDirectoryLevel1 == nil {
		return nil, fmt.Errorf("cannot extract key database without PSP Directory Level 1")
	}

	for _, entry := range pspFw.PSPDirectoryLevel1.Entries {
		if entry.Type == id {
			firmwareBytes := firmware.ImageBytes()
			start := entry.LocationOrValue
			end := start + uint64(entry.Size)
			if err := checkBoundaries(start, end, firmwareBytes); err != nil {
				return nil, fmt.Errorf("cannot extract key database from firmware image, boundary check fail: %w", err)
			}
			binary, err := NewPSPBinary(firmwareBytes[start:end])
			if err != nil {
				return nil, fmt.Errorf("could not construct PSP header from key database: %w", err)
			}
			return binary, nil
		}
	}
	return nil, fmt.Errorf("could not find PSP entry %d in PSP Directory Level 1", id)
}
