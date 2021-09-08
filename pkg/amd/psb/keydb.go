package psb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	amd_manifest "github.com/9elements/converged-security-suite/pkg/amd/manifest"
)

const keydbHeaderSize = 80

const (
	// AMDPublicKeyEntry denotes AMD public key entry in PSP Directory table
	AMDPublicKeyEntry amd_manifest.PSPDirectoryTableEntryType = 0x00

	// KeyDatabaseEntry points to region of firmware containing key database
	KeyDatabaseEntry amd_manifest.PSPDirectoryTableEntryType = 0x50
)

// KeyDatabase is a container for all keys known to the system
type KeyDatabase struct {
	db map[KeyID]*Key
}

// String returns a string representation of the key database
func (kdb *KeyDatabase) String() string {
	var s strings.Builder
	fmt.Fprintf(&s, "Number of keys in database: %d\n\n", len(kdb.db))

	for _, key := range kdb.db {
		fmt.Fprintf(&s, "%s\n\n", key.String())
	}
	return s.String()
}

// AddKey adds a key to the key database
func (kdb *KeyDatabase) AddKey(k *Key) error {
	keyID := k.KeyID()
	if _, ok := kdb.db[keyID]; ok {
		return fmt.Errorf("canont add key id %s to database, key with same id already exists", keyID.Hex())
	}
	kdb.db[keyID] = k
	return nil
}

// NewKeyDatabase builds an empty key database object
func NewKeyDatabase() *KeyDatabase {
	keydb := KeyDatabase{}
	keydb.db = make(map[KeyID]*Key)
	return &keydb
}

// GetKey returns a key if known to the KeyDatabase. If the key is not known, null is returned
func (kdb *KeyDatabase) GetKey(id KeyID) *Key {
	return nil
}

// keydbHeader represents the header pre-pended to keydb structure
type keydbHeader struct {
	dataSize        uint32
	version         uint32
	cookie          uint32
	reserved        buf36B
	customerDefined buf32B
}

func readAndCountSize(r io.Reader, order binary.ByteOrder, data interface{}, counter *uint64) error {
	if err := binary.Read(r, order, data); err != nil {
		return err
	}
	if counter != nil {
		*counter += uint64(binary.Size(data))
	}
	return nil
}

// extractKeydbHeader parses keydbHeader from binary buffer. KeyDB header is supposed to be 80 bytes long
func extractKeydbHeader(buff io.Reader) (*keydbHeader, error) {
	header := keydbHeader{}

	if err := binary.Read(buff, binary.LittleEndian, &header.dataSize); err != nil {
		return nil, fmt.Errorf("could not parse dataSize from keydb header: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &header.version); err != nil {
		return nil, fmt.Errorf("could not parse version from keydb header: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &header.cookie); err != nil {
		return nil, fmt.Errorf("could not parse cookie from keydb header: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &header.reserved); err != nil {
		return nil, fmt.Errorf("could not parse reserved region from keydb header: %w", err)
	}
	if err := binary.Read(buff, binary.LittleEndian, &header.customerDefined); err != nil {
		return nil, fmt.Errorf("could not parse customer defined region from keydb header: %w", err)
	}

	return &header, nil
}

// extractKeyEntry extracts a key object serialized in the key database.
// The structure of a key object is as follows:
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
// Even if this structure doesn't match perfectly Key structure, we still deserialize into Key object
// Some fields of Key will contain zero value, e.g. certifying key ID (which it's indirectly the AMD root
// key, as it signs the whole key database).
func extractKeyEntry(buff *bytes.Buffer) (*Key, error) {

	key := Key{}

	var (
		dataSize uint32
		numRead  uint64
	)

	if err := readAndCountSize(buff, binary.LittleEndian, &dataSize, &numRead); err != nil {
		return nil, fmt.Errorf("could not parse dataSize from key entry in keydb: %w", err)
	}

	// consider if we still have enough data to parse a whole key entry which is dataSize long.
	// dataSize includes the uint32 dataSize field itself
	if uint64(dataSize) > uint64(buff.Len())+4 {
		return nil, fmt.Errorf("buffer is not long enough (%d) to satisfy dataSize (%d) for key entry", buff.Len(), dataSize)
	}

	if err := readAndCountSize(buff, binary.LittleEndian, &key.versionID, &numRead); err != nil {
		return nil, fmt.Errorf("could not parse VersionID from key entry in keydb: %w", err)
	}

	if err := readAndCountSize(buff, binary.LittleEndian, &key.keyUsageFlag, &numRead); err != nil {
		return nil, fmt.Errorf("could not parse key usage flags from key entry in keydb: %w", err)
	}

	var publicExponent buf4B
	if err := readAndCountSize(buff, binary.LittleEndian, &publicExponent, &numRead); err != nil {
		return nil, fmt.Errorf("could not parse public exponent from key entry in keydb: %w", err)
	}
	key.exponent = publicExponent[:]

	if err := readAndCountSize(buff, binary.LittleEndian, &key.keyID, &numRead); err != nil {
		return nil, fmt.Errorf("could not parse key id from key entry in keydb: %w", err)
	}

	var keySize uint32
	if err := readAndCountSize(buff, binary.LittleEndian, &keySize, &numRead); err != nil {
		return nil, fmt.Errorf("could not parse key size from key entry in keydb: %w", err)
	}
	if keySize == 0 {
		return nil, fmt.Errorf("key size cannot be 0")
	}

	key.exponentSize = keySize
	key.modulusSize = keySize

	var reserved buf44B
	if err := readAndCountSize(buff, binary.LittleEndian, &reserved, &numRead); err != nil {
		return nil, fmt.Errorf("could not parse reserved area for key entry in keydb: %w", err)
	}

	// modulus is stored in little endian format, its size depends on the key size read
	if keySize%8 != 0 {
		return nil, fmt.Errorf("key size is not divisible by 8 (%d)", keySize)
	}

	// check if we have enough data left, based on keySize and dataSize
	if (numRead + uint64(keySize)/8) > uint64(dataSize) {
		return nil, fmt.Errorf("read so far %d, total size is %d, but key size to read is %d, which goes out of bound", numRead, dataSize, keySize)

	}
	modulus := make([]byte, keySize/8)
	if err := binary.Read(buff, binary.LittleEndian, &modulus); err != nil {
		return nil, fmt.Errorf("could not parse modulus: %w", err)
	}
	key.modulus = modulus

	return &key, nil
}

// GetKeyDB extracts the key database signed bytes obtained from KeyDatabaseEntry from PSP Table
func GetKeyDB(firmware amd_manifest.Firmware) (*KeyDatabase, error) {
	pspFw, err := amd_manifest.ParsePSPFirmware(firmware)
	if err != nil {
		return nil, fmt.Errorf("could not get key database: %w", err)
	}

	amdPk, err := extractAMDPublicKey(pspFw, firmware)
	if err != nil {
		return nil, fmt.Errorf("could no extract AMD public key from firmware: %w", err)
	}

	keyDBBinary, err := ExtractPSPBinary(KeyDatabaseEntry, pspFw, firmware)
	if err != nil {
		return nil, fmt.Errorf("could not extract KeyDatabaseEntry entry (%d) from PSP firmware: %w", KeyDatabaseEntry, err)
	}

	signature, signedData, err := keyDBBinary.GetSignature()
	if err != nil {
		return nil, fmt.Errorf("could not extract signature information from keydb binary: %w", err)
	}

	if err := signature.Validate(signedData, amdPk); err != nil {
		return nil, fmt.Errorf("could not validate KeyDB PSP Header signature with AMD Public key: %w", err)
	}

	// build a key database and add extracted keys  to it. All keys in the database are supposed to be trusted
	keyDB := NewKeyDatabase()
	if err := keyDB.AddKey(amdPk); err != nil {
		return nil, fmt.Errorf("could not add AMD key to the key database: %w", err)
	}

	buffer := bytes.NewBuffer(signedData.DataWithoutHeader())
	header, err := extractKeydbHeader(buffer)
	if err != nil {
		return nil, fmt.Errorf("could not extract keydb header: %w", header)
	}

	for {
		if buffer.Len() == 0 {
			break
		}
		key, err := extractKeyEntry(buffer)
		if err != nil {
			return nil, fmt.Errorf("could not extract key entry from key database: %w", err)
		}
		if err := keyDB.AddKey(key); err != nil {
			return nil, fmt.Errorf("cannot add key to key database: %w", err)
		}
	}
	return keyDB, nil
}
