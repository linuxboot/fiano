package psb

// Key parsing logic is based on AMD Platform Security Processor BIOS Architecture Design Guide for AMD Family 17h and Family 19h Processors
// Publication # 55758
// Issue Date: August 2020
// Revision: 1.11

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"strings"

	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
)

// KeyID is the primary identifier of a key
type KeyID Buf16B

// Hex returns a hexadecimal string representation of a KeyID
func (kid *KeyID) Hex() string {
	var s strings.Builder
	fmt.Fprintf(&s, "%x", *kid)
	return s.String()
}

// String returns the hexadecimal string representation of a KeyID
func (kid *KeyID) String() string {
	return kid.Hex()
}

// KeyIDs represents a list of KeyID
type KeyIDs []KeyID

// String returns a string representation of all KeyIDs
func (kids KeyIDs) String() string {
	if len(kids) == 0 {
		return ""
	}

	var s strings.Builder
	fmt.Fprintf(&s, "%s", kids[0].Hex())
	for _, kid := range kids[1:] {
		fmt.Fprintf(&s, ", %s", kid.Hex())
	}
	return s.String()
}

// KeyUsageFlag describes a known values for KeyUsageFlag field of AMD PSP Key structure
type KeyUsageFlag uint32

const (
	// SignAMDBootloaderPSPSMU tells that the corresponding key is authorized to sign AMD developed PSP Boot
	// Loader and AMD developed PSP FW components and SMU FW.
	// See Table 26. RSA Key Format Fields of AMD Platform Security Processor BIOS Architecture Design Guide for AMD Family 17h and 19h Processors
	// Revision 1.11
	SignAMDBootloaderPSPSMU KeyUsageFlag = 0

	// SignBIOS tells that the corresponding key is authorized to sign BIOS
	SignBIOS KeyUsageFlag = 1

	// SignAMDOEMPSP tells that the corresponding key is authorized to sign PSP FW (both AMD developed and OEM developed)
	SignAMDOEMPSP KeyUsageFlag = 2

	// PSBSignBIOS tells that a key is authorized to sign BIOS for platform secure boot.
	// See Table 8. RSA Key Format Fields of Enabling Platform Secure Boot
	// for AMD Family 17h Models 00h–0Fh and 30h–3Fh and Family 19h Models 00h–0Fh Processor-Based Server Platforms
	// Revision 0.91
	PSBSignBIOS KeyUsageFlag = 8
)

// KeyData represents the binary format (as it is stored in an image) of the information associated with a key
type KeyData struct {
	VersionID       uint32
	KeyID           KeyID
	CertifyingKeyID Buf16B
	KeyUsageFlag    KeyUsageFlag
	Reserved        Buf16B
	ExponentSize    uint32
	ModulusSize     uint32
	Exponent        []byte
	Modulus         []byte
}

// Key structure extracted from the firmware
type Key struct {
	data KeyData
}

// PlatformBindingInfo describes information of BIOS Signing Key to Platform Binding information
type PlatformBindingInfo struct {
	VendorID        uint8
	KeyRevisionID   uint8
	PlatformModelID uint8
}

func (b PlatformBindingInfo) String() string {
	var s strings.Builder
	fmt.Fprintf(&s, "Vendor ID: %X\n", b.VendorID)
	fmt.Fprintf(&s, "Key Revision ID: %X\n", b.KeyRevisionID)
	fmt.Fprintf(&s, "Platform Model ID: %X\n", b.PlatformModelID)
	return s.String()
}

// GetPlatformBindingInfo for PSBSignBIOS key returns BIOS Signing Key to Platform Binding information
func GetPlatformBindingInfo(k *Key) (PlatformBindingInfo, error) {
	if k.data.KeyUsageFlag != PSBSignBIOS {
		return PlatformBindingInfo{}, fmt.Errorf("not a PSBSignBios key usage flag: %v", k.data.KeyUsageFlag)
	}
	return parsePlatformBinding(k.data.Reserved), nil
}

func parsePlatformBinding(reserved Buf16B) PlatformBindingInfo {
	return PlatformBindingInfo{
		VendorID:        reserved[0],
		KeyRevisionID:   reserved[1] & 7,  // Bits 0:3 => Key Revision ID
		PlatformModelID: reserved[1] << 3, // Bits 4:7 => Platform Model ID
	}
}

// SecurityFeatureVector represents a security feature selection vector of BIOS OEM key
type SecurityFeatureVector struct {
	DisableBIOSKeyAntiRollback bool
	DisableAMDBIOSKeyUse       bool
	DisableSecureDebugUnlock   bool
}

func (sfv SecurityFeatureVector) String() string {
	var s strings.Builder
	fmt.Fprintf(&s, "DISABLE_BIOS_KEY_ANTI_ROLLBACK: %t\n", sfv.DisableBIOSKeyAntiRollback)
	fmt.Fprintf(&s, "DISABLE_AMD_BIOS_KEY_USE: %t\n", sfv.DisableAMDBIOSKeyUse)
	fmt.Fprintf(&s, "DISABLE_SECURE_DEBUG_UNLOCK: %t\n", sfv.DisableSecureDebugUnlock)
	return s.String()
}

// GetSecurityFeatureVector for PSBSignBIOS key returns a security feature selection vector
func GetSecurityFeatureVector(k *Key) (SecurityFeatureVector, error) {
	if k.data.KeyUsageFlag != PSBSignBIOS {
		return SecurityFeatureVector{}, fmt.Errorf("not a PSBSignBios key usage flag: %v", k.data.KeyUsageFlag)
	}
	return parseSecurityFeatureVector(k.data.Reserved), nil
}

func parseSecurityFeatureVector(reserved Buf16B) SecurityFeatureVector {
	return SecurityFeatureVector{
		DisableBIOSKeyAntiRollback: reserved[3]&1 == 1,
		DisableAMDBIOSKeyUse:       (reserved[3]<<1)&1 == 1,
		DisableSecureDebugUnlock:   (reserved[3]<<2)&1 == 1,
	}
}

// Key creation functions manage two slightly different key structures available in firmware:
//
// 1) Those serialized into key tokens
// 2) Those serialized into the key database
//
// Format 2) is as follow:
//
// type key struct {
// 		dataSize uint32
//		version uint32
//		keyUsageFlag uint32
// 		publicExponent [4]uint8
//		keyID	[16]uint8
//		keySize uint32
//		reserved Buf44B
//		modulus []byte
// }
//
// From a bytes buffer, there is no way to distinguish between the two cases above, so an indication
// of which format to use should come from the caller (by calling NewKey<TYPE>).
//
// Both formats will be deserialized into Key structure. Some fields of Key might contain zero value
// (e.g. certifying key ID for keys extracted from the key database, which is indirectly the AMD root
// key as it signs the whole key database).
//
// If the key is a token key, the signature is validated.
// Additional safety checks are implemented during serialization:
// if a `certifyingKeyID` is retrieved from the buffer and it's not null, a KeySet must be available for validation,
// or an error will be returned. Callers however are ultimately responsible to make sure that a KeySet is passed if
// a key should be validated.

func zeroCertifyingKeyID(key *Key) bool {
	for _, v := range key.data.CertifyingKeyID {
		if v != 0 {
			return false
		}
	}
	return true
}

// readExponent reads exponent value from a buffer, assuming exponent size
// has already been populated.
func readExponent(buff *bytes.Buffer, key *Key) error {
	if key.data.ExponentSize%8 != 0 {
		return newErrInvalidFormat(fmt.Errorf("exponent size is not divisible by 8"))
	}
	exponent := make([]byte, key.data.ExponentSize/8)
	if err := binary.Read(buff, binary.LittleEndian, &exponent); err != nil {
		return newErrInvalidFormat(fmt.Errorf("could not parse exponent: %w", err))
	}
	key.data.Exponent = exponent
	return nil
}

// readModulus reads modulus value from a buffer, assuming modulus size
// has already been populated
func readModulus(buff *bytes.Buffer, key *Key) error {
	if key.data.ModulusSize%8 != 0 {
		return newErrInvalidFormat(fmt.Errorf("modulus size is not divisible by 8"))
	}

	modulus := make([]byte, key.data.ModulusSize/8)
	if err := binary.Read(buff, binary.LittleEndian, &modulus); err != nil {
		return newErrInvalidFormat(fmt.Errorf("could not parse modulus: %w", err))
	}
	key.data.Modulus = modulus
	return nil
}

// newTokenOrRootKey creates the common parts of Token and Root keys
func newTokenOrRootKey(buff *bytes.Buffer) (*Key, error) {

	key := Key{}

	if err := binary.Read(buff, binary.LittleEndian, &key.data.VersionID); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse VersionID: %w", err))
	}
	if err := binary.Read(buff, binary.LittleEndian, &key.data.KeyID); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse KeyID: %w", err))
	}
	if err := binary.Read(buff, binary.LittleEndian, &key.data.CertifyingKeyID); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse Certifying KeyID: %w", err))
	}
	if err := binary.Read(buff, binary.LittleEndian, &key.data.KeyUsageFlag); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse Key Usage Flag: %w", err))
	}
	if err := binary.Read(buff, binary.LittleEndian, &key.data.Reserved); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse reserved area: %w", err))
	}
	if err := binary.Read(buff, binary.LittleEndian, &key.data.ExponentSize); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse exponent size: %w", err))
	}
	if err := binary.Read(buff, binary.LittleEndian, &key.data.ModulusSize); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse modulus size: %w", err))
	}

	if err := readExponent(buff, &key); err != nil {
		return nil, err
	}

	if err := readModulus(buff, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// NewRootKey creates a new root key object which is considered trusted without any need for signature check
func NewRootKey(buff *bytes.Buffer) (*Key, error) {
	key, err := newTokenOrRootKey(buff)
	if err != nil {
		return nil, fmt.Errorf("cannot parse root key: %w", err)
	}

	if key.data.KeyID != key.data.CertifyingKeyID {
		return nil, newErrInvalidFormat(fmt.Errorf("root key must have certifying key ID == key ID (key ID: %x, certifying key ID: %x)", key.data.KeyID, key.data.CertifyingKeyID))
	}
	return key, err

}

// NewTokenKey create a new key object from a signed token
func NewTokenKey(buff *bytes.Buffer, keySet KeySet) (*Key, error) {

	raw := buff.Bytes()

	key, err := newTokenOrRootKey(buff)
	if err != nil {
		return nil, fmt.Errorf("could not create new token key: %w", err)
	}

	signingKeyID := KeyID(key.data.CertifyingKeyID)
	signingKey := keySet.GetKey(signingKeyID)
	if signingKey == nil {
		return nil, fmt.Errorf("could not find signing key with ID %s for key token key", signingKeyID.Hex())
	}

	signatureSize, err := signingKey.SignatureSize()
	if err != nil {
		return nil, &SignatureCheckError{signingKey: signingKey, err: fmt.Errorf("could not get signature length of a key: %w", err)}
	}

	// validate the signature of the new token key
	signature := make([]byte, signatureSize)
	if err := binary.Read(buff, binary.LittleEndian, &signature); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse signature from key token: %w", err))
	}

	// A key extracted from a signed token has the following structure:
	// * 64 bytes header
	// * exponent
	// * modulus
	// * signature.
	//
	// Exponent, modulus and signature are all of the same size. Only the latter is not signed, hence the lenght
	// of the signed payload is header size + 2 * exponent/modulus size.
	lenSigned := uint64(64 + 2*key.data.ModulusSize/8)
	if uint64(len(raw)) < lenSigned {
		return nil, newErrInvalidFormat(fmt.Errorf("length of signed token is not sufficient: expected > %d, got %d", lenSigned, len(raw)))
	}

	// Validate the signature of the raw token
	if _, err := NewSignedBlob(reverse(signature), raw[:lenSigned], signingKey); err != nil {
		return nil, fmt.Errorf("could not validate the signature of token key: %w", err)
	}
	return key, nil
}

// NewKeyFromDatabase creates a new key object from key database entry
func NewKeyFromDatabase(buff *bytes.Buffer) (*Key, error) {
	key := Key{}

	var (
		dataSize uint32
		numRead  uint64
	)

	if err := readAndCountSize(buff, binary.LittleEndian, &dataSize, &numRead); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse dataSize: %w", err))
	}

	// consider if we still have enough data to parse a whole key entry which is dataSize long.
	// dataSize includes the uint32 dataSize field itself
	if uint64(dataSize) > uint64(buff.Len())+4 {
		return nil, newErrInvalidFormat(fmt.Errorf("buffer is not long enough (%d) to satisfy dataSize (%d)", buff.Len(), dataSize))
	}

	if err := readAndCountSize(buff, binary.LittleEndian, &key.data.VersionID, &numRead); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse VersionID: %w", err))
	}

	if err := readAndCountSize(buff, binary.LittleEndian, &key.data.KeyUsageFlag, &numRead); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse key usage flags: %w", err))
	}

	var publicExponent Buf4B
	if err := readAndCountSize(buff, binary.LittleEndian, &publicExponent, &numRead); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse public exponent: %w", err))
	}
	key.data.Exponent = publicExponent[:]

	if err := readAndCountSize(buff, binary.LittleEndian, &key.data.KeyID, &numRead); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse key id: %w", err))
	}

	var keySize uint32
	if err := readAndCountSize(buff, binary.LittleEndian, &keySize, &numRead); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse key size: %w", err))
	}
	if keySize == 0 {
		return nil, newErrInvalidFormat(fmt.Errorf("key size cannot be 0"))
	}

	if keySize%8 != 0 {
		return nil, newErrInvalidFormat(fmt.Errorf("key size is not divisible by 8 (%d)", keySize))
	}

	key.data.ExponentSize = keySize
	key.data.ModulusSize = keySize

	var reserved Buf44B
	if err := readAndCountSize(buff, binary.LittleEndian, &reserved, &numRead); err != nil {
		return nil, newErrInvalidFormat(fmt.Errorf("could not parse reserved area: %w", err))
	}
	// check if we have enough data left, based on keySize and dataSize
	if (numRead + uint64(keySize)/8) > uint64(dataSize) {
		return nil, newErrInvalidFormat(fmt.Errorf("inconsistent header, read so far %d, total size is %d, key size to read is %d, which goes out of bound", numRead, dataSize, keySize))
	}

	if err := readModulus(buff, &key); err != nil {
		return nil, err
	}

	if !zeroCertifyingKeyID(&key) {
		return nil, newErrInvalidFormat(fmt.Errorf("key extracted from key database should have zero certifying key ID"))
	}

	return &key, nil
}

// String returns a string representation of the key
func (k *Key) String() string {
	var s strings.Builder

	pubKey, err := k.Get()
	if err != nil {
		fmt.Fprintf(&s, "could not get RSA key from raw bytes: %v\n", err)
		return s.String()
	}

	fmt.Fprintf(&s, "Version ID: 0x%x\n", k.data.VersionID)
	fmt.Fprintf(&s, "Key ID: 0x%s\n", k.data.KeyID.Hex())
	fmt.Fprintf(&s, "Certifying Key ID: 0x%x\n", k.data.CertifyingKeyID)
	fmt.Fprintf(&s, "Key Usage Flag: 0x%x\n", k.data.KeyUsageFlag)
	if k.data.KeyUsageFlag == PSBSignBIOS {
		fmt.Fprintf(&s, "%s", parsePlatformBinding(k.data.Reserved))
		fmt.Fprintf(&s, "%s", parseSecurityFeatureVector(k.data.Reserved))
	}
	fmt.Fprintf(&s, "Exponent size: 0x%x (dec %d) \n", k.data.ExponentSize, k.data.ExponentSize)
	fmt.Fprintf(&s, "Modulus size: 0x%x (dec %d)\n", k.data.ModulusSize, k.data.ModulusSize)

	switch rsaKey := pubKey.(type) {
	case *rsa.PublicKey:
		fmt.Fprintf(&s, "Exponent: 0x%d\n", rsaKey.E)
	default:
		fmt.Fprintf(&s, "Exponent: key is not RSA, cannot get decimal exponent\n")
	}

	fmt.Fprintf(&s, "Modulus: 0x%x\n", k.data.Modulus)
	return s.String()
}

// Get returns the PublicKey object from golang standard library.
// AMD Milan supports only RSA Keys (2048, 4096), future platforms
// might add support for additional key types.
func (k *Key) Get() (interface{}, error) {
	if err := k.checkValid(); err != nil {
		return nil, err
	}

	N := big.NewInt(0)
	E := big.NewInt(0)

	// modulus and exponent are read as little endian
	rsaPk := rsa.PublicKey{N: N.SetBytes(reverse(k.data.Modulus)), E: int(E.SetBytes(reverse(k.data.Exponent)).Int64())}
	return &rsaPk, nil
}

// SignatureSize returns the size of the signature
func (k *Key) SignatureSize() (int, error) {
	if err := k.checkValid(); err != nil {
		return 0, err
	}
	return len(k.data.Modulus), nil
}

func (k *Key) checkValid() error {
	if len(k.data.Exponent) == 0 {
		return fmt.Errorf("invalid key: exponent size is 0")
	}
	if len(k.data.Modulus) == 0 {
		return fmt.Errorf("invalid key: modulus size is 0")
	}
	return nil
}

// GetKeys returns all the keys known to the system in the form of a KeySet.
// The firmware itself contains a key database, but that is not comprehensive
// of all the keys known to the system (e.g. additional keys might be OEM key,
// ABL signing key, etc.).
func GetKeys(amdFw *amd_manifest.AMDFirmware, level uint) (KeySet, error) {
	keySet := NewKeySet()
	err := getKeysFromDatabase(amdFw, level, keySet)
	if err != nil {
		return keySet, fmt.Errorf("could not get key from table into KeySet: %w", err)
	}

	// Extract ABL signing key (entry 0x0A in PSP Directory), which is signed with AMD Public Key.
	pubKeyBytes, err := ExtractPSPEntry(amdFw, level, ABLPublicKey)
	if err != nil {
		return keySet, fmt.Errorf("could not extract raw PSP entry for ABL Public Key: %w", err)
	}
	ablPk, err := NewTokenKey(bytes.NewBuffer(pubKeyBytes), keySet)
	if err != nil {
		return keySet, addFirmwareItemToError(err, newPSPDirectoryEntryItem(uint8(level), ABLPublicKey))
	}

	err = keySet.AddKey(ablPk, ABLKey)
	if err != nil {
		return keySet, fmt.Errorf("could not add ABL signing key to key set: %w", err)
	}

	// Extract OEM signing key (entry 0x05 in BIOS Directory table)
	// in PSB disabled this entry doesn't exist
	pubKeyBytes, err = ExtractBIOSEntry(amdFw, level, OEMSigningKeyEntry, 0)
	if err != nil {
		if !errors.As(err, &ErrNotFound{}) {
			return keySet, fmt.Errorf("could not extract raw BIOS directory entry for OEM Public Key: %w", err)
		}
	} else {
		oemPk, err := NewTokenKey(bytes.NewBuffer(pubKeyBytes), keySet)
		if err != nil {
			return keySet, fmt.Errorf("could not extract OEM public key: %w", err)
		}

		err = keySet.AddKey(oemPk, OEMKey)
		if err != nil {
			return keySet, fmt.Errorf("could not add OEM signing key to key set: %w", err)
		}
	}
	return keySet, nil
}
