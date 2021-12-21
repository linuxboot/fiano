//go:generate manifestcodegen

package manifest

import (
	"encoding/binary"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/manifest/common/pretty"
)

var (
	binaryOrder = binary.LittleEndian
)

// StructInfo is the common part of any structure of a manifest
type StructInfo struct {
	ID          StructureID `json:"StructInfoID"`
	Version     uint8       `json:"StructInfoVersion"`
	Variable0   uint8       `json:"StructInfoVariable0"`
	ElementSize uint16      `json:"StructInfoElementSize"`
}

// StructInfo just returns StructInfo, it is a handy method if StructInfo
// is included anonymously to another type.
func (s StructInfo) StructInfo() StructInfo {
	return s
}

// StructureID is the magic ID string used to identify the structure type
// in the manifest
type StructureID [8]byte

// String returns the ID as a string.
func (s StructureID) String() string {
	return string(s[:])
}

// Structure is an abstraction of a structure of a manifest.
type Structure interface {
	io.ReaderFrom
	io.WriterTo
	TotalSize() uint64
	// PrettyString returns the whole object as a structured string.
	PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string
}

// Element is an abstraction of an element of a manifest.
type Element interface {
	Structure
	ReadDataFrom(r io.Reader) (int64, error)
	GetStructInfo() StructInfo
	SetStructInfo(StructInfo)
}

// ElementsContainer is an abstraction of set of elements of a manifest (for
// example: the root structure of BPM).
type ElementsContainer interface {
	Structure
	GetFieldByStructID(structID string) interface{}
}

// Manifest is an abstract manifest.
type Manifest interface {
	Structure
}
