//go:generate manifestcodegen

package manifest

import (
	"encoding/binary"
	"io"
)

var (
	binaryOrder = binary.LittleEndian
)

type StructInfo struct {
	ID          StructureID
	Version     uint8
	Variable0   uint8
	ElementSize uint16
}

func (s StructInfo) StructInfo() StructInfo {
	return s
}

type StructureID [8]byte

// String returns the ID as a string.
func (s StructureID) String() string {
	return string(s[:])
}

type Structure interface {
	io.ReaderFrom
	io.WriterTo
	TotalSize() uint64
	// PrettyString returns the whole object as a structured string.
	PrettyString(depth uint, withHeader bool) string
}

type Element interface {
	Structure
	ReadDataFrom(r io.Reader) (int64, error)
	GetStructInfo() StructInfo
	SetStructInfo(StructInfo)
}

type ElementsContainer interface {
	Structure
	GetFieldByStructID(structID string) interface{}
}

// Manifest is an abstract manifest.
type Manifest interface {
	Structure
}
