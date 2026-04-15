// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// All custom types definitions for the metadata pkg that are shared
// and/or duplicated (for e.g. used both in bg and cbnt packages wo.
// any modifications)
type (
	ManifestFieldType string

	LayoutField struct {
		ID    int
		Name  string
		Size  func() uint64
		Value func() any
		Type  ManifestFieldType
		// optional list reader onluy to be used for types that contain
		// ManifestFieldList
		ReadList func(r io.Reader) (int64, error)
		// optional list writer to be used for types that contain
		// ManifestFieldList
		WriteList func(w io.Writer) (int64, error)
	}

	// Structure is an abstraction of a structure of a manifest.
	Structure interface {
		io.ReaderFrom
		io.WriterTo
		TotalSize() uint64
		SizeOf(id int) (uint64, error)
		OffsetOf(id int) (uint64, error)
		Layout() []LayoutField
		Validate() error
		// PrettyString returns the whole object as a structured string.
		PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string
	}

	// Element is an abstraction of an element of a manifest.
	Element interface {
		Structure
		GetStructInfo() StructInfo
		SetStructInfo(StructInfo)
	}

	Manifest interface {
		Structure
	}

	// StructureList is an abstraction of slice of Structures
	StructureList interface {
		Structures() []Structure
	}
)
