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
	"math"
	"math/big"

	"strings"

	amd_manifest "github.com/9elements/converged-security-suite/pkg/amd/manifest"
)

// KeyType represents the type of the key being deserialized
type KeyType string

const (
	// TokenKey represents a key deserialized from a signed token
	TokenKey KeyType = "TokenKey"
	// RootKey represents the root AMD Public Key. There should be only one key of this type
	RootKey KeyType = "RootKey"
	// KeyDatabaseKey represents a key deserialized from a key database entry
	KeyDatabaseKey = "KeyDatabaseKey"
)

// KeyID is the primary identifier of a key
type KeyID buf16B

// Hex returns a hexadecimal string representation of a KeyID
func (kid *KeyID) Hex() string {
	var s strings.Builder
	fmt.Fprintf(&s, "%x", *kid)
	return s.String()
}

// Key structure extracted from the firmware
type Key struct {
	versionID       uint32
	keyID           KeyID
	certifyingKeyID buf16B
	keyUsageFlag    uint32
	reserved        buf16B
	exponentSize    uint32
	modulusSize     uint32
	exponent        []byte
	modulus         []byte
}

// NewKey creates a new Key object based on raw bytes. There are two slightly different
// key structures available in firmware:
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
//		reserved buf44B
//		modulus []byte
// }
//
// From a bytes buffer, there is no way to distinguish between the two cases above, so an indication
// of which format to use should come from the caller.
//
// Both formats will be deserialized into Key structure. Some fields of Key might contain zero value
// (e.g. certifying key ID for keys extracted from the key database, which is indirectly the AMD root
// key as it signs the whole key database).
//
// newKey also validates the signature of the key being deserialized if a KeySet is provided. Additional
// safety checks are implemented during serialization: if a `certifyingKeyID` is retrieved from the buffer
// and it's not null, a KeySet must be available for validation, or an error will be returned. Callers
// however are ultimately responsible to make sure that a KeySet is passed if a key should be validated.
func newKey(buff *bytes.Buffer, keyType KeyType, keySet *KeySet) (*Key, error) {

	if keyType == TokenKey && keySet == nil {
		return nil, fmt.Errorf("key of type %s must have its signature validated, so a KeySet is necessary (passed nil)", keyType)
	}

	key := Key{}

	if keyType == KeyDatabaseKey {

		var (
			dataSize uint32
			numRead  uint64
		)

		if err := readAndCountSize(buff, binary.LittleEndian, &dataSize, &numRead); err != nil {
			return nil, fmt.Errorf("could not parse dataSize: %w", err)
		}

		// consider if we still have enough data to parse a whole key entry which is dataSize long.
		// dataSize includes the uint32 dataSize field itself
		if uint64(dataSize) > uint64(buff.Len())+4 {
			return nil, fmt.Errorf("buffer is not long enough (%d) to satisfy dataSize (%d)", buff.Len(), dataSize)
		}

		if err := readAndCountSize(buff, binary.LittleEndian, &key.versionID, &numRead); err != nil {
			return nil, fmt.Errorf("could not parse VersionID: %w", err)
		}

		if err := readAndCountSize(buff, binary.LittleEndian, &key.keyUsageFlag, &numRead); err != nil {
			return nil, fmt.Errorf("could not parse key usage flags: %w", err)
		}

		var publicExponent buf4B
		if err := readAndCountSize(buff, binary.LittleEndian, &publicExponent, &numRead); err != nil {
			return nil, fmt.Errorf("could not parse public exponent: %w", err)
		}
		key.exponent = publicExponent[:]

		if err := readAndCountSize(buff, binary.LittleEndian, &key.keyID, &numRead); err != nil {
			return nil, fmt.Errorf("could not parse key id: %w", err)
		}

		var keySize uint32
		if err := readAndCountSize(buff, binary.LittleEndian, &keySize, &numRead); err != nil {
			return nil, fmt.Errorf("could not parse key size: %w", err)
		}
		if keySize == 0 {
			return nil, fmt.Errorf("key size cannot be 0")
		}

		if keySize%8 != 0 {
			return nil, fmt.Errorf("key size is not divisible by 8 (%d)", keySize)
		}

		key.exponentSize = keySize
		key.modulusSize = keySize

		var reserved buf44B
		if err := readAndCountSize(buff, binary.LittleEndian, &reserved, &numRead); err != nil {
			return nil, fmt.Errorf("could not parse reserved area: %w", err)
		}
		// check if we have enough data left, based on keySize and dataSize
		if (numRead + uint64(keySize)/8) > uint64(dataSize) {
			return nil, fmt.Errorf("inconsistent header, read so far %d, total size is %d, key size to read is %d, which goes out of bound", numRead, dataSize, keySize)
		}

	} else {

		if err := binary.Read(buff, binary.LittleEndian, &key.versionID); err != nil {
			return nil, fmt.Errorf("could not parse VersionID: %w", err)
		}
		if err := binary.Read(buff, binary.LittleEndian, &key.keyID); err != nil {
			return nil, fmt.Errorf("could not parse KeyID: %w", err)
		}
		if err := binary.Read(buff, binary.LittleEndian, &key.certifyingKeyID); err != nil {
			return nil, fmt.Errorf("could not parse Certifying KeyID: %w", err)
		}
		if err := binary.Read(buff, binary.LittleEndian, &key.keyUsageFlag); err != nil {
			return nil, fmt.Errorf("could not parse Key Usage Flag: %w", err)
		}
		if err := binary.Read(buff, binary.LittleEndian, &key.reserved); err != nil {
			return nil, fmt.Errorf("could not parse reserved area: %w", err)
		}
		if err := binary.Read(buff, binary.LittleEndian, &key.exponentSize); err != nil {
			return nil, fmt.Errorf("could not parse exponent size: %w", err)
		}
		if err := binary.Read(buff, binary.LittleEndian, &key.modulusSize); err != nil {
			return nil, fmt.Errorf("could not parse modulus size: %w", err)
		}
	}

	if math.Mod(float64(key.exponentSize), float64(8)) != 0 {
		return nil, fmt.Errorf("exponent size is not divisible by 8")
	}
	if math.Mod(float64(key.modulusSize), float64(8)) != 0 {
		return nil, fmt.Errorf("modulus size is not divisible by 8")
	}

	// read the trailing part of the key, which is either exponend and modulus or only modulus
	// depending on the type of key (e.g. for keys of type KeyDatabaseKey, exponent has already
	// been read)
	if keyType == TokenKey || keyType == RootKey {
		exponent := make([]byte, key.exponentSize/8)
		if err := binary.Read(buff, binary.LittleEndian, &exponent); err != nil {
			return nil, fmt.Errorf("could not parse exponent: %w", err)
		}
		key.exponent = exponent
	}

	modulus := make([]byte, key.modulusSize/8)
	if err := binary.Read(buff, binary.LittleEndian, &modulus); err != nil {
		return nil, fmt.Errorf("could not parse modulus: %w", err)
	}
	key.modulus = modulus

	// TODO: key of type TokenKey should have the signature validated
	return &key, nil
}

// NewRootKey creates a new root key object which is considered trusted without any need for signature check
func NewRootKey(buff *bytes.Buffer) (*Key, error) {
	return newKey(buff, RootKey, nil)
}

// NewTokenKey create a new key object from a signed token
func NewTokenKey(buff *bytes.Buffer, keySet *KeySet) (*Key, error) {
	if keySet == nil {
		return nil, fmt.Errorf("creating a TokenKey requires a KeySet passed as argument")
	}
	return newKey(buff, TokenKey, keySet)
}

// NewKeyFromDatabase creates a new key object from key database entry
func NewKeyFromDatabase(buff *bytes.Buffer) (*Key, error) {
	return newKey(buff, KeyDatabaseKey, nil)
}

// KeyID return the key ID of the key object
func (k *Key) KeyID() KeyID {
	return k.keyID
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
	fmt.Fprintf(&s, "Key ID: 0x%s\n", k.keyID.Hex())
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

// GetKeys returns all the keys known to the system in the form of a KeySet.
// The firmware itself contains a key database, but that is not comprehensive
// of all the keys known to the system (e.g. additional keys might be OEM key,
// ABL signing key, etc.).
func GetKeys(firmware amd_manifest.Firmware) (*KeySet, error) {
	keySet := NewKeySet()
	err := getKeysFromDatabase(firmware, keySet)
	return keySet, err
}
