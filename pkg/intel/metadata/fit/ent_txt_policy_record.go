// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// EntryTXTPolicyRecord represents a FIT entry of type "TXT Policy Record" (0x0A)
type EntryTXTPolicyRecord struct{ EntryBase }

var _ EntryCustomGetDataSegmentSizer = (*EntryTXTPolicyRecord)(nil)

// Init initializes the entry using EntryHeaders and firmware image.
func (entry *EntryTXTPolicyRecord) CustomGetDataSegmentSize(firmware io.ReadSeeker) (uint64, error) {
	// TXT policy record has no data section and the Address field is used to store the data.
	return 0, nil
}

var _ EntryCustomRecalculateHeaderser = (*EntryTXTPolicyRecord)(nil)

// CustomRecalculateHeaders recalculates metadata to be consistent with data.
// For example, it fixes checksum, data size, entry type and so on.
func (entry *EntryTXTPolicyRecord) CustomRecalculateHeaders() error {
	entryBase := entry.GetEntryBase()
	entryBase.DataSegmentBytes = nil
	hdr := &entryBase.Headers
	hdr.TypeAndIsChecksumValid.SetType(EntryTypeTXTPolicyRecord)

	// See 4.9.10 of the FIT specification.
	hdr.TypeAndIsChecksumValid.SetIsChecksumValid(false)
	// See 4.9.11 of the FIT specification.
	hdr.Size.SetUint32(0)
	return nil
}

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
		result := EntryTXTPolicyRecordDataFlatPointer(entry.Headers.Address.Pointer())
		return result, nil
	case 1:
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], entry.Headers.Address.Pointer())
		var dataParsed EntryTXTPolicyRecordDataIndexedIO
		err := binary.Read(bytes.NewReader(b[:]), binary.LittleEndian, &dataParsed)
		if err != nil {
			return nil, fmt.Errorf("unable to parse EntryTXTPolicyRecordDataIndexedIO: %w", err)
		}
		return &dataParsed, nil
	}

	return nil, &ErrInvalidTXTPolicyRecordVersion{entry.Headers.Version}
}
