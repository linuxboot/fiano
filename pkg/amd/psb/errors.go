// Copyright 2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package psb

import (
	"errors"
	"fmt"

	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
)

// SignatureCheckError is an error type which indicates that signature of an element cannot be validated against its signing key
type SignatureCheckError struct {
	signingKey    *Key
	signedElement FirmwareItem
	err           error
}

// Error returns the string representation of SignatureCheckError
func (m *SignatureCheckError) Error() string {
	if m.signedElement == nil {
		return fmt.Sprintf("signature does not validate against signing key %s: %s", m.signingKey.data.KeyID.Hex(), m.err.Error())
	}
	return fmt.Sprintf("signature of element %s does not validate against signing key %s: %s", m.signedElement, m.signingKey.data.KeyID.Hex(), m.err.Error())
}

func (m *SignatureCheckError) Unwrap() error {
	return m.err
}

// SigningKey returns the SigningKey associated to the error. Might return nil value
func (m *SignatureCheckError) SigningKey() *Key {
	return m.signingKey
}

// SignedElement returns an optional item whose signature check failed
func (m *SignatureCheckError) SignedElement() FirmwareItem {
	return m.signedElement
}

// UnknownSigningKeyError is an error type which indicates that the signing key is unknown
type UnknownSigningKeyError struct {
	signedElement FirmwareItem
	keyID         KeyID
}

// SignedElement returns an optional item whose signature check failed
func (s *UnknownSigningKeyError) SignedElement() FirmwareItem {
	return s.signedElement
}

// Error returns the string representation of the UnknownSigningKeyError
func (s *UnknownSigningKeyError) Error() string {
	if s.signedElement == nil {
		return fmt.Sprintf("key ID '%s' is unknown", s.keyID.Hex())
	}
	return fmt.Sprintf("failed to check signature of element '%s' key ID '%s' is unknown", s.signedElement, s.keyID.Hex())
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
	return fmt.Sprintf("entry '0x%X' (%s) instance %d of bios directory level %d", biosEntry.Entry, BIOSEntryType(biosEntry.Entry), biosEntry.Instance, biosEntry.Level)
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
	return fmt.Sprintf("entry '0x%X' (%s) of psp directory level %d", pspEntry.Entry, PSPEntryType(pspEntry.Entry), pspEntry.Level)
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

func addFirmwareItemToError(err error, item FirmwareItem) error {
	if err == nil {
		return nil
	}

	var sigCheckErr *SignatureCheckError
	if errors.As(err, &sigCheckErr) {
		if sigCheckErr.signedElement == nil {
			return &SignatureCheckError{signingKey: sigCheckErr.signingKey, signedElement: item, err: sigCheckErr.err}
		}
		return err
	}

	var unknownKey *UnknownSigningKeyError
	if errors.As(err, &unknownKey) {
		if unknownKey.signedElement == nil {
			return &UnknownSigningKeyError{keyID: unknownKey.keyID, signedElement: item}
		}
		return err
	}

	var notFoundErr ErrNotFound
	if errors.As(err, &notFoundErr) {
		if notFoundErr.item == nil {
			return ErrNotFound{item: item}
		}
		return err
	}

	var invalidFormatErr ErrInvalidFormat
	if errors.As(err, &invalidFormatErr) {
		if notFoundErr.item == nil {
			return ErrNotFound{item: item}
		}
		return err
	}
	return err
}
