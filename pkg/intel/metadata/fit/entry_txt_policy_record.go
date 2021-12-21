// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// EntryTXTPolicyRecordDataInterface is a parsed TXT Policy Record entry
type EntryTXTPolicyRecordDataInterface interface {
	IsTXTEnabled() bool
}

// EntryTXTPolicyRecordDataIndexedIO is a parsed TXT Policy Record entry of
// version 1.
type EntryTXTPolicyRecordDataIndexedIO struct {
	IndexRegisterIOAddress uint16
	DataRegisterIOAddress  uint16
	AccessWidth            uint8
	BitPosition            uint8
	Index                  uint16
}

// IsTXTEnabled returns true if TXT is enabled.
func (entryData *EntryTXTPolicyRecordDataIndexedIO) IsTXTEnabled() bool {
	panic("not implemented")
}

// EntryTXTPolicyRecordDataFlatPointer is a parsed TXT Policy Record entry
// of version 0
type EntryTXTPolicyRecordDataFlatPointer uint64

// TPMPolicyPointer returns the TPM Policy pointer.
func (entryData EntryTXTPolicyRecordDataFlatPointer) TPMPolicyPointer() uint64 {
	return uint64(entryData & 0x7fffffffffffffff)
}

// IsTXTEnabled returns true if TXT is enabled.
func (entryData EntryTXTPolicyRecordDataFlatPointer) IsTXTEnabled() bool {
	return entryData&0x8000000000000000 != 0
}

// Parse parses TXT Policy Record entry
func (entry *EntryTXTPolicyRecord) Parse() (EntryTXTPolicyRecordDataInterface, error) {
	switch entry.Headers.Version {
	case 0:
		ptr := binary.LittleEndian.Uint64(entry.DataBytes)
		result := EntryTXTPolicyRecordDataFlatPointer(ptr)
		return result, nil
	case 1:
		var dataParsed EntryTXTPolicyRecordDataIndexedIO
		err := binary.Read(bytes.NewReader(entry.DataBytes), binary.LittleEndian, &dataParsed)
		if err != nil {
			return nil, fmt.Errorf("unable to parse EntryTXTPolicyRecordDataIndexedIO: %w", err)
		}
		return &dataParsed, nil
	}

	return nil, &ErrInvalidTXTPolicyRecordVersion{entry.Headers.Version}
}
