// Copyright 2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package psb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
)

// KeyType represents the type of the key stored in KeySet
type KeyType string

const (
	// OEMKey represents the OEM signing key
	OEMKey KeyType = "OEMKey"
	// AMDRootKey represents the AMD signing key
	AMDRootKey KeyType = "AMDRootKey"
	// KeyDatabaseKey represents a key extracted from KeyDatabase
	KeyDatabaseKey KeyType = "KeyDatabaseKey"
	// ABLKey represents the ABL signing key
	ABLKey KeyType = "ALBKey"
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
func (kdb KeySet) AddKey(k *Key, keyType KeyType) error {
	if _, ok := kdb.db[k.data.KeyID]; ok {
		return fmt.Errorf("cannot add key id %s to set, key with same id already exists", k.data.KeyID.Hex())
	}

	kdb.db[k.data.KeyID] = k
	// assume the key cannot be already present in the keyType mapping
	kdb.keyType[keyType] = append(kdb.keyType[keyType], k.data.KeyID)
	return nil
}

// NewKeySet builds an empty key set object
func NewKeySet() KeySet {
	keySet := KeySet{}
	keySet.db = make(map[KeyID]*Key)
	keySet.keyType = make(map[KeyType][]KeyID)
	return keySet
}

// GetKey returns a key if known to the KeySet. If the key is not known, null is returned
func (kdb KeySet) GetKey(id KeyID) *Key {
	if kdb.db == nil {
		return nil
	}
	return kdb.db[id]
}

// AllKeyIDs returns a list of all KeyIDs stored in the KeySet
func (kdb KeySet) AllKeyIDs() KeyIDs {
	keyIDs := make(KeyIDs, 0, len(kdb.db))
	for keyID := range kdb.db {
		keyIDs = append(keyIDs, keyID)
	}
	return keyIDs
}

// KeysetFromType returns a KeySet containing all KeyIDs of a specific type
func (kdb KeySet) KeysetFromType(keyType KeyType) (KeySet, error) {
	if _, ok := kdb.keyType[keyType]; !ok {
		return NewKeySet(), newErrNotFound(nil)
	}
	keySet := NewKeySet()
	for _, keyID := range kdb.keyType[keyType] {
		key := kdb.GetKey(keyID)
		if key == nil {
			return NewKeySet(), newErrInvalidFormat(fmt.Errorf("KeySet in inconsistent state, no key is present with keyID %s", keyID.Hex()))
		}

		err := keySet.AddKey(key, keyType)
		if err != nil {
			return NewKeySet(), fmt.Errorf("unable to add key %s: %w", keyID, err)
		}
	}
	return keySet, nil
}

// keyDBHeader represents the header pre-pended to keydb structure
type keyDBHeader struct {
	DataSize        uint32
	Version         uint32
	Cookie          uint32
	Reserved        Buf36B
	CustomerDefined Buf32B
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
func extractKeydbHeader(buff io.Reader) (*keyDBHeader, error) {
	header := keyDBHeader{}

	if err := binary.Read(buff, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("could not read key database header: %w", err)
	}

	return &header, nil
}

// parseKeyDatabase parses a raw buffer representing a key database and adds all extracted key
// to the associated keySet. The raw buffer must be stripped off of the PSP header and the signature
// appended at the end.
func parseKeyDatabase(rawDB []byte, keySet KeySet) error {

	buff := bytes.NewBuffer(rawDB)
	_, err := extractKeydbHeader(buff)
	if err != nil {
		return fmt.Errorf("could not extract keydb header: %w", err)
	}

	for {
		if buff.Len() == 0 {
			break
		}
		key, err := NewKeyFromDatabase(buff)
		if err != nil {
			return fmt.Errorf("could not extract key entry from key database: %w", err)
		}
		if err := keySet.AddKey(key, KeyDatabaseKey); err != nil {
			return fmt.Errorf("cannot add key to key database: %w", err)
		}
	}

	return nil
}

// getKeysFromDatabase extracts the keys in the firmware key database and adds them to the KeySet passed
// as argument after validating the signature of the database itself
func getKeysFromDatabase(amdFw *amd_manifest.AMDFirmware, pspLevel uint, keySet KeySet) error {

	/**
	 * PSP Directory Level 2 does not contain the AMD
	 * Public Root Keys, so we are forced to use PSP Directory
	 * Level 1 to get them, and not have it configurable
	 */
	pubKeyBytes, err := ExtractPSPEntry(amdFw, 1, AMDPublicKeyEntry)
	if err != nil {
		return fmt.Errorf("could not extract raw PSP entry for AMD Public Key: %w", err)
	}
	amdPk, err := NewRootKey(bytes.NewBuffer(pubKeyBytes))
	if err != nil {
		return addFirmwareItemToError(err, newPSPDirectoryEntryItem(uint8(pspLevel), AMDPublicKeyEntry))
	}

	// All keys which get added the KeySet are supposed to be trusted. AMD root key is trusted as a result of being matched against a
	// "source of truth" (in hardware, this is a hash burnt into the CPU. Software tooling should check it against some external
	// reference).
	if err := keySet.AddKey(amdPk, AMDRootKey); err != nil {
		return fmt.Errorf("could not add AMD key to the key database: %w", err)
	}

	data, err := ExtractPSPEntry(amdFw, pspLevel, KeyDatabaseEntry)
	if err != nil {
		return fmt.Errorf("could not extract entry 0x%x (KeyDatabaseEntry) from PSP table: %w", KeyDatabaseEntry, err)
	}

	binary, err := newPSPBinary(data)
	if err != nil {
		return newErrInvalidFormatWithItem(newPSPDirectoryEntryItem(uint8(pspLevel), KeyDatabaseEntry),
			fmt.Errorf("could not create PSB binary from raw data for entry 0x%x (KeyDatabaseEntry): %w", KeyDatabaseEntry, err))
	}

	// getSignedBlob returns the whole PSP blob as a signature-validated structure.
	signedBlob, err := binary.getSignedBlob(keySet)
	if err != nil {
		return addFirmwareItemToError(err, newPSPDirectoryEntryItem(uint8(pspLevel), KeyDatabaseEntry))
	}

	// We need to strip off pspHeader to get the content which actually represents the keys database
	signedData := signedBlob.SignedData()
	if len(signedData) <= pspHeaderSize {
		return newErrInvalidFormatWithItem(newPSPDirectoryEntryItem(uint8(pspLevel), KeyDatabaseEntry),
			fmt.Errorf("length of key database entry (%d) is less than pspHeader length (%d)", len(signedData), pspHeaderSize))
	}

	return parseKeyDatabase(signedData[pspHeaderSize:], keySet)
}
