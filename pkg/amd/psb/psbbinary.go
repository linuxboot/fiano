package psb

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// pspHeaderSize represents the size of the header pre-pended to PSP binaries
const pspHeaderSize = 0x100

// signedDataStart indicates the start address of signed data content within a PSP binary
const signedDataStart = 0x0

// sizeSignedToSignatureParametersLen is the size of the header from sizeSigned field to signatureParameters
const sizeSignedToSignatureParametersLen = 32

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

// getSignedBlob returns the PSP binary object as a signature-validated SignedBlob structure
func (b *PSPBinary) getSignedBlob(keyDB KeySet) (*SignedBlob, error) {

	if b.header.sizeSigned == 0 {
		return nil, fmt.Errorf("size of signed data cannot be 0 for PSPBinary")
	}
	if b.header.sizeImage == 0 {
		return nil, fmt.Errorf("size of image cannot be 0 for PSPBinary")
	}

	// Try use signatureParameters as KeyID field for the signing key which signed the PSP binary.
	// We need to look-up the signing key to infer the expected size of the signature.
	signingKeyID := KeyID(b.header.signatureParameters)
	signingKey := keyDB.GetKey(signingKeyID)
	if signingKey == nil {
		return nil, fmt.Errorf("could not find signing key with ID %s", signingKeyID.Hex())
	}

	// The recommended value for RSA exponent is 0x10001. The specification does not enforce
	// that modulus and exponent buffer size should be the same, but so far this has been the
	// case. This should probably be clarified with AMD and possibly be removed in the future.
	if signingKey.modulusSize != signingKey.exponentSize {
		return nil, fmt.Errorf("exponent size (%d) and modulus size (%d) do not match", signingKey.modulusSize, signingKey.exponentSize)
	}

	sizeSignature := signingKey.modulusSize / 8

	sizeImage := uint32(0)
	sizeSignedImage := uint32(0)
	if b.header.compressionOptions == 0x0 {
		// the image is not compressed, sizeSigned and sizeImage constitute the source of truth
		if b.header.sizeSigned > b.header.sizeImage {
			return nil, fmt.Errorf("size of signed image cannot be > size of image (%d > %d)", b.header.sizeSigned, b.header.sizeImage)
		}
		// sizeSigned does not include the size of the header
		sizeSignedImage = b.header.sizeSigned + pspHeaderSize
		sizeImage = b.header.sizeImage
	} else {
		// the image is compressed, SizeFWSigned is to be ignored and instead compressedImageSize should be
		// taken into consideration and aligned to 16 bits. PSP header size is not included in compresseImageSize.
		alignment := uint32(0x10)
		sizeSignedImage = (b.header.compressedImageSize+alignment-1) & ^(alignment-1) + pspHeaderSize
		sizeImage = sizeSignedImage + sizeSignature
	}

	if sizeImage <= sizeSignature {
		return nil, fmt.Errorf("sizeImage (%d) cannot be <= of sizeSignature (%d)", sizeImage, sizeSignature)
	}
	signatureStart := sizeImage - sizeSignature
	signatureEnd := signatureStart + sizeSignature

	if err := checkBoundaries(uint64(signatureStart), uint64(signatureEnd), b.raw); err != nil {
		return nil, fmt.Errorf("could not extract signature from raw PSPBinary: %w", err)
	}

	signedDataEnd := signedDataStart + sizeSignedImage
	if err := checkBoundaries(uint64(signedDataStart), uint64(signedDataEnd), b.raw); err != nil {
		return nil, fmt.Errorf("could not extract signed data from raw PSPBinary: %w", err)
	}

	signature := b.raw[signatureStart:signatureEnd]

	signedData := b.raw[signedDataStart:signedDataEnd]
	if len(signedData) <= pspHeaderSize {
		return nil, fmt.Errorf("PSP binary cannot be smaller than or equal to header size")
	}
	return NewSignedBlob(signature, signedData, signingKey, "PSP binary")
}

// newPSPBinary creates a PSPBinary object, with associated header
func newPSPBinary(data []byte) (*PSPBinary, error) {

	pspBinary := PSPBinary{}
	pspBinary.raw = make([]byte, len(data))
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
		return nil, fmt.Errorf("could not read signatureParameters: %w", err)
	}

	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header.compressionOptions); err != nil {
		return nil, fmt.Errorf("could not read compressionOptions: %w", err)
	}

	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header.securityPatchLevel); err != nil {
		return nil, fmt.Errorf("could not read securityPatchLevel: %w", err)
	}

	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header.uncompressedImageSize); err != nil {
		return nil, fmt.Errorf("could not read uncompressedImageSize: %w", err)
	}

	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header.compressedImageSize); err != nil {
		return nil, fmt.Errorf("could not read compressedImageSize: %w", err)
	}

	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header.compressionParameters); err != nil {
		return nil, fmt.Errorf("could not read compressionParameters: %w", err)
	}

	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header.imageVersion); err != nil {
		return nil, fmt.Errorf("could not read imageVersion: %w", err)
	}

	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header.apuFamilyID); err != nil {
		return nil, fmt.Errorf("could not read apuFamilyID: %w", err)
	}

	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header.firmwareLoadAddress); err != nil {
		return nil, fmt.Errorf("could not read firmwareLoadAddress: %w", err)
	}

	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header.sizeImage); err != nil {
		return nil, fmt.Errorf("could not read sizeImage: %w", err)
	}
	return &pspBinary, nil
}
