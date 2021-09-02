package psb

// Key parsing logic is based on AMD Platform Security Processor BIOS Architecture Design Guide for AMD Family 17h and Family 19h Processors
// Publication # 55758
// Issue Date: August 2020
// Revision: 1.11

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"

	"strings"

	amd_manifest "github.com/9elements/converged-security-suite/pkg/amd/manifest"
)

type buf16B = [16]uint8

// Key structure extracted from the firmware
type Key struct {
	versionID       uint32
	keyID           buf16B
	certifyingKeyID buf16B
	keyUsageFlag    uint32
	reserved        buf16B
	exponentSize    uint32
	modulusSize     uint32
	exponent        []byte
	modulus         []byte
}

// String returns a string representation of the key
func (k *Key) String() string {
	var s strings.Builder

	pubKey, err := k.Get()
	if err != nil {
		fmt.Fprintf(&s, "could not get RSA key from raw bytes: %v\n", err)
		return s.String()
	}

	fmt.Fprintf(&s, "Version ID: 0x%x\n", k.versionID)
	fmt.Fprintf(&s, "Key ID: 0x%x\n", k.keyID)
	fmt.Fprintf(&s, "Certifying Key ID: 0x%x\n", k.certifyingKeyID)
	fmt.Fprintf(&s, "Key Usage Flag: 0x%x\n", k.keyUsageFlag)
	fmt.Fprintf(&s, "Exponent size: 0x%x (dec %d) \n", k.exponentSize, k.exponentSize)
	fmt.Fprintf(&s, "Modulus size: 0x%x (dec %d)\n", k.modulusSize, k.modulusSize)

	switch rsaKey := pubKey.(type) {
	case *rsa.PublicKey:
		fmt.Fprintf(&s, "Exponent: 0x%d\n", rsaKey.E)
	default:
		fmt.Fprintf(&s, "Exponent: key is not RSA, cannot get decimal exponent\n")
	}

	fmt.Fprintf(&s, "Modulus: 0x%x\n", k.modulus)
	return s.String()
}

// Get returns the PublicKey object from golang standard library.
// AMD Milan supports only RSA Keys (2048, 4096), future platforms
// might add support for additional key types.
func (k *Key) Get() (interface{}, error) {

	if len(k.exponent) == 0 {
		return nil, fmt.Errorf("could not build public key without exponent")
	}
	if len(k.modulus) == 0 {
		return nil, fmt.Errorf("could not build public key without modulus")
	}

	N := big.NewInt(0)
	E := big.NewInt(0)

	// modulus and exponent are read as little endian
	rsaPk := rsa.PublicKey{N: N.SetBytes(reverse(k.modulus)), E: int(E.SetBytes(reverse(k.exponent)).Int64())}
	return &rsaPk, nil
}

func reverse(s []byte) []byte {
	if s == nil || len(s) == 0 {
		return nil
	}
	d := make([]byte, len(s))
	copy(d, s)

	for right := len(d)/2 - 1; right >= 0; right-- {
		left := len(d) - 1 - right
		d[right], d[left] = d[left], d[right]
	}
	return d
}

func checkBoundaries(start, end uint64, blob []byte) error {
	if start > uint64(len(blob)) {
		return fmt.Errorf("boundary check error: start is beyond blob bondary (%d > %d)", start, len(blob))
	}
	if end > uint64(len(blob)) {
		return fmt.Errorf("boundary check error: start is beyond blob bondary (%d > %d)", end, len(blob))
	}
	if start > end {
		return fmt.Errorf("boundary check error: start > end (%d > %d)", start, end)
	}
	return nil
}

// parsePubKey parses a public key structure from system firmware
func parsePubKey(buff io.Reader) (*Key, error) {
	pk := Key{}

	if err := binary.Read(buff, binary.LittleEndian, &pk.versionID); err != nil {
		return nil, fmt.Errorf("could not parse VersionID: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &pk.keyID); err != nil {
		return nil, fmt.Errorf("could not parse KeyID: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &pk.certifyingKeyID); err != nil {
		return nil, fmt.Errorf("could not parse Certifying KeyID: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &pk.keyUsageFlag); err != nil {
		return nil, fmt.Errorf("could not parse Key Usage Flag: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &pk.reserved); err != nil {
		return nil, fmt.Errorf("could not parse reserved area: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &pk.exponentSize); err != nil {
		return nil, fmt.Errorf("could not parse exponent size: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &pk.modulusSize); err != nil {
		return nil, fmt.Errorf("could not parse modulus size: %w", err)
	}

	if math.Mod(float64(pk.exponentSize), float64(8)) != 0 {
		return nil, fmt.Errorf("exponent size is not divisible by 8")
	}
	if math.Mod(float64(pk.modulusSize), float64(8)) != 0 {
		return nil, fmt.Errorf("modulus size is not divisible by 8")
	}

	modSize := pk.modulusSize / 8
	expSize := pk.exponentSize / 8

	exponent := make([]byte, expSize)
	if err := binary.Read(buff, binary.LittleEndian, &exponent); err != nil {
		return nil, fmt.Errorf("could not parse exponent: %w", err)
	}

	pk.exponent = exponent

	modulus := make([]byte, modSize)
	if err := binary.Read(buff, binary.LittleEndian, &modulus); err != nil {
		return nil, fmt.Errorf("could not parse modulus: %w", err)
	}
	pk.modulus = modulus

	return &pk, nil
}

// extractAMDPublicKey parses entry 0x01 in PSP Directory to obtain AMD Public Key.
// Refer to Appendix B, Key Format of document # 55758
func extractAMDPublicKey(pspFw *amd_manifest.PSPFirmware, firmware amd_manifest.Firmware) (*Key, error) {

	if pspFw == nil {
		return nil, fmt.Errorf("cannot extract AMD public key from nil PSP Firmware")
	}

	if pspFw.PSPDirectoryLevel1 == nil {
		return nil, fmt.Errorf("cannot extract AMD public key without PSP Directory Level 1")
	}

	for _, entry := range pspFw.PSPDirectoryLevel1.Entries {
		if entry.Type == AMDPublicKeyEntry {
			firmwareBytes := firmware.ImageBytes()
			start := entry.LocationOrValue
			end := start + uint64(entry.Size)
			if err := checkBoundaries(start, end, firmwareBytes); err != nil {
				return nil, fmt.Errorf("cannot extract AMD Public key from image: %w", err)
			}

			pk, err := parsePubKey(bytes.NewBuffer(firmwareBytes[start:end]))
			if err != nil {
				return nil, fmt.Errorf("could not extract AMD Public key: %w", err)
			}

			return pk, nil
		}
	}
	return nil, fmt.Errorf("could not find AMDPublicKeyEntry (%d) in PSP Directory Level 1", AMDPublicKeyEntry)
}
