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
	Nonce                 buf16B
	HeaderVersion         uint32
	SizeSigned            uint32
	EncryptionOptions     uint32
	IkekType              uint8
	Reserved0             buf3B
	EncryptionParameters  buf16B
	SignatureOption       uint32
	SignatureAlgorithmID  uint32
	SignatureParameters   buf16B
	CompressionOptions    uint32
	SecurityPatchLevel    uint32
	UncompressedImageSize uint32
	CompressedImageSize   uint32
	CompressionParameters buf8B
	ImageVersion          uint32
	ApuFamilyID           uint32
	FirmwareLoadAddress   uint32
	SizeImage             uint32
	SizeFwUnsigned        uint32
	FirmwareSplitAddress  uint32
	Reserved              buf4B
	FwType                uint8
	FwSubType             uint8
	Reserved1             uint16
	EncryptionKey         buf16B
	SigningInfo           buf16B
	FwSpecificData        buf32B
	DebugEncKey           buf16B

	// There should be 48 bytes of padding after the last field of the header,
	// which can be ignored. What we care about is the signature of the binary,
	// stored at the bottom of the image described by the header. This can be
	// looked up via sizeSigned and sizeImage

}

// Version returns the headerVersion field of the pspHeader structure
func (h *PspHeader) Version() uint32 {
	return h.HeaderVersion
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

	if b.header.SizeSigned == 0 {
		return nil, newErrInvalidFormat(fmt.Errorf("size of signed data cannot be 0 for PSPBinary"))
	}
	if b.header.SizeImage == 0 {
		return nil, newErrInvalidFormat(fmt.Errorf("size of image cannot be 0 for PSPBinary"))
	}

	// Try use signatureParameters as KeyID field for the signing key which signed the PSP binary.
	// We need to look-up the signing key to infer the expected size of the signature.
	signingKeyID := KeyID(b.header.SignatureParameters)
	signingKey := keyDB.GetKey(signingKeyID)
	if signingKey == nil {
		return nil, &UnknownSigningKeyError{keyID: signingKeyID}
	}

	// The recommended value for RSA exponent is 0x10001. The specification does not enforce
	// that modulus and exponent buffer size should be the same, but so far this has been the
	// case. This should probably be clarified with AMD and possibly be removed in the future.
	if signingKey.ModulusSize != signingKey.ExponentSize {
		return nil, fmt.Errorf("exponent size (%d) and modulus size (%d) do not match", signingKey.ModulusSize, signingKey.ExponentSize)
	}

	sizeSignature := signingKey.ModulusSize / 8

	sizeImage := uint32(0)
	sizeSignedImage := uint32(0)
	if b.header.CompressionOptions == 0x0 {
		// the image is not compressed, sizeSigned and sizeImage constitute the source of truth
		if b.header.SizeSigned > b.header.SizeImage {
			return nil, newErrInvalidFormat(fmt.Errorf("size of signed image cannot be > size of image (%d > %d)", b.header.SizeSigned, b.header.SizeImage))
		}
		// sizeSigned does not include the size of the header
		sizeSignedImage = b.header.SizeSigned + pspHeaderSize
		sizeImage = b.header.SizeImage
	} else {
		// the image is compressed, SizeFWSigned is to be ignored and instead compressedImageSize should be
		// taken into consideration and aligned to 16 bits. PSP header size is not included in compresseImageSize.
		alignment := uint32(0x10)
		sizeSignedImage = (b.header.CompressedImageSize+alignment-1) & ^(alignment-1) + pspHeaderSize
		sizeImage = sizeSignedImage + sizeSignature
	}

	if sizeImage <= sizeSignature {
		return nil, newErrInvalidFormat(fmt.Errorf("sizeImage (%d) cannot be <= of sizeSignature (%d)", sizeImage, sizeSignature))
	}
	signatureStart := sizeImage - sizeSignature
	signatureEnd := signatureStart + sizeSignature

	if err := checkBoundaries(uint64(signatureStart), uint64(signatureEnd), b.raw); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not extract signature from raw PSPBinary: %w", err))
	}

	signedDataEnd := signedDataStart + sizeSignedImage
	if err := checkBoundaries(uint64(signedDataStart), uint64(signedDataEnd), b.raw); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not extract signed data from raw PSPBinary: %w", err))
	}

	signature := b.raw[signatureStart:signatureEnd]

	signedData := b.raw[signedDataStart:signedDataEnd]
	if len(signedData) <= pspHeaderSize {
		return nil, newErrInvalidFormat(fmt.Errorf("PSP binary cannot be smaller than or equal to header size"))
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

	if err := binary.Read(buff, binary.LittleEndian, &pspBinary.header); err != nil {
		return nil, fmt.Errorf("could not parse header of PSP Binary: %w", err)
	}
	return &pspBinary, nil
}
