package psb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// SizeHeader represents the size of the PSP header
const SizeHeader = 0x100

// PSPHeader represents a generic header structure pre-pended to all PSP Blobs
type PSPHeader struct {
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
	// which can be ignored. What we care about is the signature of the blob,
	// stored at the bottom of the image described by the header. This can be
	// looked up via sizeSigned and sizeImage

	// keep track of the raw data of the PSP Header
	raw []byte
}

// GetSignature implements SignatureGetter interface for PSPHeader
func (h *PSPHeader) GetSignature() (*Signature, *SignedData, error) {

	if h.sizeSigned == 0 {
		return nil, nil, fmt.Errorf("size of signed data cannot be 0 for PSPHeader")
	}
	if h.sizeImage == 0 {
		return nil, nil, fmt.Errorf("size of image cannot be 0 for PSPHeader")
	}

	if h.sizeSigned > h.sizeImage {
		return nil, nil, fmt.Errorf("size of signed image cannot be > size of image (%d > %d)", h.sizeSigned, h.sizeImage)
	}

	// TODO: for the moment, assume the signature is 512 bytes long (RSA4096).
	// GetSignature should be given in input the key database, so that
	// the fingerprint of the key which signed the header can be compared
	// with the known keys to decide the expected length of the signature.
	// We need full support for parsing key database before being able to
	// pass it to GetSignature().

	sizeSignature := uint32(512)
	signatureStart := h.sizeImage - sizeSignature
	signatureEnd := signatureStart + sizeSignature
	if err := checkBoundaries(uint64(signatureStart), uint64(signatureEnd), h.raw); err != nil {
		return nil, nil, fmt.Errorf("could not extract signature from raw PSPHeader: %w", err)
	}

	signedDataStart := uint32(0)
	signedDataEnd := signedDataStart + h.sizeSigned + SizeHeader
	if err := checkBoundaries(uint64(signedDataStart), uint64(signedDataEnd), h.raw); err != nil {
		return nil, nil, fmt.Errorf("could not extract signed data from raw PSPHeader: %w", err)
	}

	var keyFingerprint strings.Builder
	fmt.Fprintf(&keyFingerprint, "%x", h.signatureParameters)
	signature := NewSignature(h.raw[signatureStart:signatureEnd], keyFingerprint.String())
	signedData := NewSignedData(h.raw[signedDataStart:signedDataEnd])

	return &signature, &signedData, nil
}

// NewPSPHeader creates a PSPHeader structure
func NewPSPHeader(data []byte) (*PSPHeader, error) {

	header := PSPHeader{}
	header.raw = make([]byte, len(data), len(data))
	copied := copy(header.raw, data)
	if copied != len(data) {
		return nil, fmt.Errorf("expected %d copied data from for raw header, got %d", len(data), copied)
	}

	buff := bytes.NewBuffer(header.raw)

	if err := binary.Read(buff, binary.LittleEndian, &header.nonce); err != nil {
		return nil, fmt.Errorf("could not parse nonce from PSPHeader: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &header.headerVersion); err != nil {
		return nil, fmt.Errorf("could not parse header version from PSPHeader: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &header.sizeSigned); err != nil {
		return nil, fmt.Errorf("could not parse sizeSigned from PSPHeader: %w", err)

	}

	// skip parsing up to signatureParameters, all other fields are not relevant at the moment
	skipUntilSignatureParametersLen := 32
	unknown := make([]byte, skipUntilSignatureParametersLen)
	if err := binary.Read(buff, binary.LittleEndian, unknown); err != nil {
		return nil, fmt.Errorf("could not read header until skipUntilSignatureParametersLen: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &header.signatureParameters); err != nil {
		return nil, fmt.Errorf("could not read header until sizeImage: %w", err)
	}

	// skip parsing up to sizeImage, all other fields are not relevant at the moment
	skipUntilSizeImageLen := 36
	unknown = make([]byte, skipUntilSizeImageLen)
	if err := binary.Read(buff, binary.LittleEndian, unknown); err != nil {
		return nil, fmt.Errorf("could not read header until sizeImage: %w", err)
	}

	if err := binary.Read(buff, binary.LittleEndian, &header.sizeImage); err != nil {
		return nil, fmt.Errorf("could not read sizeImage: %w", err)
	}
	return &header, nil
}
