// Copyright 2017-2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package bg

import (
	"encoding/binary"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

var (
	binaryOrder = binary.LittleEndian
)

type StructInfo struct {
	ID      StructureID `json:"StructInfoID"`
	Version uint8       `json:"StructInfoVersion"`
}

func (s StructInfo) StructInfo() StructInfo {
	return s
}

type StructureID [8]byte

func (s StructureID) String() string {
	return string(s[:])
}

type Structure interface {
	io.ReaderFrom
	io.WriterTo
	TotalSize() uint64
	PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string
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

type Manifest interface {
	Structure
}
