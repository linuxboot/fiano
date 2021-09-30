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

// KeyType represents the type of the key stored in KeySet
type KeyType uint8

const (
	// OEMKey represents the OEM signing key
	OEMKey KeyType = iota
	// AMDRootKey represents the AMD signing key
	AMDRootKey
	// KeyDatabaseKey represents a key extracted from KeyDatabase
	KeyDatabaseKey
	// ABLKey represents the ABL signing key
	ABLKey
)

// KeySet is a container for all keys known to the system
type KeySet struct {
	// db holds a mapping between keyID and key
	db map[KeyID]*Key
	// keyType holds a mapping betweek KeyType and KeyID
	keyType map[KeyType][]KeyID
}

// String returns a string representation of the key in the set
func (kdb *KeySet) String() string {
	var s strings.Builder
	fmt.Fprintf(&s, "Number of keys in key set: %d\n\n", len(kdb.db))

	for _, key := range kdb.db {
		fmt.Fprintf(&s, "%s\n\n", key.String())
	}
	return s.String()
}

// AddKey adds a key to the key set
func (kdb *KeySet) AddKey(k *Key, keyType KeyType) error {
	keyID := k.KeyID()
	if _, ok := kdb.db[keyID]; ok {
		return fmt.Errorf("canont add key id %s to set, key with same id already exists", keyID.Hex())
	}

	kdb.db[keyID] = k
	// assume the key cannot be already present in the keyType mapping
	kdb.keyType[keyType] = append(kdb.keyType[keyType], k.KeyID())
	return nil
}

// NewKeySet builds an empty key set object
func NewKeySet() *KeySet {
	keydb := KeySet{}
	keydb.db = make(map[KeyID]*Key)
	keydb.keyType = make(map[KeyType][]KeyID)
	return &keydb
}

// GetKey returns a key if known to the KeySet. If the key is not known, null is returned
func (kdb *KeySet) GetKey(id KeyID) *Key {
	return kdb.db[id]
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

// getKeysFromDatabase extracts the keys in the firmware key database and adds them to the KeySet passed
// as argument after validating the signature of the database itself
func getKeysFromDatabase(firmware amd_manifest.Firmware, keySet *KeySet) error {
	pspFw, err := amd_manifest.ParsePSPFirmware(firmware)
	if err != nil {
		return fmt.Errorf("could not get key database from firmware: %w", err)
	}

	// extract AMD Root Key
	pubKeyBytes, err := extractRawPSPEntry(AMDPublicKeyEntry, pspFw, firmware)
	if err != nil {
		return fmt.Errorf("could not extract raw PSP entry for AMD Public Key")
	}
	amdPk, err := NewRootKey(bytes.NewBuffer(pubKeyBytes))
	if err != nil {
		return fmt.Errorf("could not create AMD Root key from raw bytes: %w", err)
	}

	// All keys which get added the KeySet are supposed to be trusted. AMD root key is trusted as a result of being matched against a
	// "source of truth" (in hardware, this is a hash burnt into the CPU. Software tooling should check it against some external
	// reference).
	if err := keySet.AddKey(amdPk, AMDRootKey); err != nil {
		return fmt.Errorf("could not add AMD key to the key database: %w", err)
	}

	data, err := extractRawPSPEntry(KeyDatabaseEntry, pspFw, firmware)
	if err != nil {
		return fmt.Errorf("could not extract entry 0x%x (KeyDatabaseEntry) from PSP table: %w", KeyDatabaseEntry, err)
	}

	binary, err := newPSPBinary(data)
	if err != nil {
		return fmt.Errorf("could not create PSB binary from raw data for entry 0x%x (KeyDatabaseEntry): %w", KeyDatabaseEntry, err)
	}

	// getSignedBlob returns the whole PSP blob as a signature-validated structure.
	signedBlob, err := binary.getSignedBlob(keySet)
	if err != nil {
		return fmt.Errorf("could not validate signature of PSB binary: %w", err)
	}

	// We need to strip off pspHeader to get the content which actually represents the keys database
	signedData := signedBlob.SignedData()
	if len(signedData) <= pspHeaderSize {
		return fmt.Errorf("length of key database entry (%d) is less than pspHeader length (%d)", len(signedData), pspHeaderSize)
	}

	buffer := bytes.NewBuffer(signedData[pspHeaderSize:])
	_, err = extractKeydbHeader(buffer)
	if err != nil {
		return fmt.Errorf("could not extract keydb header: %w", err)
	}

	for {
		if buffer.Len() == 0 {
			break
		}
		key, err := NewKeyFromDatabase(buffer)
		if err != nil {
			return fmt.Errorf("could not extract key entry from key database: %w", err)
		}
		if err := keySet.AddKey(key, KeyDatabaseKey); err != nil {
			return fmt.Errorf("cannot add key to key database: %w", err)
		}
	}
	return nil
}
