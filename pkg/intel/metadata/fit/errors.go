package fit

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit/consts"
)

// ErrACMInvalidKeySize means ACM entry has invalid key size
type ErrACMInvalidKeySize struct {
	ExpectedKeySize uint64
	RealKeySize     uint64
}

func (err *ErrACMInvalidKeySize) Error() string {
	return fmt.Sprintf("invalid key size, expected:%d, real:%d",
		err.ExpectedKeySize, err.RealKeySize)
}

// ErrUnknownACMHeaderVersion means ACM entry has invalid header version
type ErrUnknownACMHeaderVersion struct {
	ACHeaderVersion ACModuleHeaderVersion
}

func (err *ErrUnknownACMHeaderVersion) Error() string {
	return fmt.Sprintf("unknown ACM header version: %v", err.ACHeaderVersion)
}

// ErrInvalidTXTPolicyRecordVersion means TXT Policy entry has invalid version.
type ErrInvalidTXTPolicyRecordVersion struct {
	EntryVersion EntryVersion
}

func (err *ErrInvalidTXTPolicyRecordVersion) Error() string {
	return fmt.Sprintf("invalid TXT policy record version: %v", err.EntryVersion)
}

// ErrExpectedFITHeadersMagic means FIT magic string was not found where
// it was expected.
type ErrExpectedFITHeadersMagic struct {
	Received []byte
}

func (err *ErrExpectedFITHeadersMagic) Error() string {
	return fmt.Sprintf("string '%s' was expected as the Address value of the FIT header entry, but received: '%s'",
		consts.FITHeadersMagic, err.Received)
}

// ErrNotFound literally means "not found".
type ErrNotFound struct{}

func (ErrNotFound) Error() string {
	return "not found"
}
