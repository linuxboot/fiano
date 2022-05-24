package psb

import (
	"fmt"
	"strings"

	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
)

// SignatureCheckError is an error type which indicates that signature of an element cannot be validated against its signing key
type SignatureCheckError struct {
	signingKey    *Key
	signedElement string
	err           error
}

// Error returns the string representation of SignatureCheckError
func (m *SignatureCheckError) Error() string {
	var s strings.Builder
	keyID := m.signingKey.KeyID
	fmt.Fprintf(&s, "signature of element %s does not validate against signing key %s: %s", m.signedElement, keyID.Hex(), m.err.Error())
	return s.String()
}

// SigningKey returns the SigningKey associated to the error. Might return nil value
func (m *SignatureCheckError) SigningKey() *Key {
	return m.signingKey
}

// UnknownSigningKeyError is an error type which indicates that the signing key is unknown
type UnknownSigningKeyError struct {
	keyID KeyID
}

// Error returns the string representation of the UnknownSigningKeyError
func (s *UnknownSigningKeyError) Error() string {
	return fmt.Sprintf("key ID %s is unknown", s.keyID.Hex())
}

// FirmwareItem is a special item that references a PSP firmware item and could be one of the following types:
// DirectoryType or BIOSDirectoryEntryItem or PSPDirectoryEntryItem
type FirmwareItem interface{}

func newDirectoryItem(directory DirectoryType) FirmwareItem {
	return directory
}

// BIOSDirectoryEntryItem determines a BIOS directory entry
type BIOSDirectoryEntryItem struct {
	Level    uint8
	Entry    amd_manifest.BIOSDirectoryTableEntryType
	Instance uint8
}

func (biosEntry BIOSDirectoryEntryItem) String() string {
	return fmt.Sprintf("entry '0x%X' instance %d of bios directory level %d", biosEntry.Entry, biosEntry.Instance, biosEntry.Level)
}

func newBIOSDirectoryEntryItem(level uint8, entry amd_manifest.BIOSDirectoryTableEntryType, instance uint8) FirmwareItem {
	return BIOSDirectoryEntryItem{
		Level:    level,
		Entry:    entry,
		Instance: instance,
	}
}

// PSPDirectoryEntryItem determines a PSP directory entry
type PSPDirectoryEntryItem struct {
	Level uint8
	Entry amd_manifest.PSPDirectoryTableEntryType
}

func (pspEntry PSPDirectoryEntryItem) String() string {
	return fmt.Sprintf("entry '0x%X' of psp directory level %d", pspEntry.Entry, pspEntry.Level)
}

func newPSPDirectoryEntryItem(level uint8, entry amd_manifest.PSPDirectoryTableEntryType) PSPDirectoryEntryItem {
	return PSPDirectoryEntryItem{
		Level: level,
		Entry: entry,
	}
}

// ErrNotFound describes a situation when firmware item is not found
type ErrNotFound struct {
	item FirmwareItem
}

// GetItem returns a not found item
func (err ErrNotFound) GetItem() FirmwareItem {
	return err.item
}

// Error returns the string representation of the UnknownSigningKeyError
func (err ErrNotFound) Error() string {
	if err.item == nil {
		return "not found"
	}
	return fmt.Sprintf("'%s' is not found", err.item)
}

func newErrNotFound(item FirmwareItem) ErrNotFound {
	return ErrNotFound{
		item: item,
	}
}

// ErrInvalidFormat describes a situation when parsing of firmware failed because of invalid format
type ErrInvalidFormat struct {
	item FirmwareItem
	err  error
}

// GetItem returns the affected item (could be nil)
func (err ErrInvalidFormat) GetItem() FirmwareItem {
	return err.item
}

func (err ErrInvalidFormat) Error() string {
	return fmt.Sprintf("'%s' has invalid format format: '%s'", err.item, err.err.Error())
}

func (err ErrInvalidFormat) Unwrap() error {
	return err.err
}

func newErrInvalidFormatWithItem(item FirmwareItem, err error) ErrInvalidFormat {
	return ErrInvalidFormat{item: item, err: err}
}

func newErrInvalidFormat(err error) ErrInvalidFormat {
	return ErrInvalidFormat{err: err}
}
