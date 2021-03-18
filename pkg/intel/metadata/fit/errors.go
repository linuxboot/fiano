package fit

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit/consts"
)

type ErrACMInvalidKeySize struct {
	ExpectedKeySize uint64
	RealKeySize     uint64
}

func (err *ErrACMInvalidKeySize) Error() string {
	return fmt.Sprintf("invalid key size, expected:%d, real:%d",
		err.ExpectedKeySize, err.RealKeySize)
}

type ErrUnknownACMHeaderVersion struct {
	ACHeaderVersion ACModuleHeaderVersion
}

func (err *ErrUnknownACMHeaderVersion) Error() string {
	return fmt.Sprintf("unknown ACM header version: %v", err.ACHeaderVersion)
}

type ErrInvalidTXTPolicyRecordVersion struct {
	EntryVersion EntryVersion
}

func (err *ErrInvalidTXTPolicyRecordVersion) Error() string {
	return fmt.Sprintf("invalid TXT policy record version: %v", err.EntryVersion)
}

type ErrExpectedFITHeadersMagic struct {
	Received []byte
}

func (err *ErrExpectedFITHeadersMagic) Error() string {
	return fmt.Sprintf("string '%s' was expected as the Address value of the FIT header entry, but received: '%s'",
		consts.FITHeadersMagic, err.Received)
}
