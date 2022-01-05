// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/hashicorp/go-multierror"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit/consts"
	"github.com/xaionaro-go/bytesextra"
)

// Entry is the interface common to any FIT entry
type Entry interface {
	// GetEntryBase returns EntryBase (which contains metadata of the Entry).
	GetEntryBase() *EntryBase
}

// EntryCustomGetDataSegmentSizer is an extension of Entry which overrides the default
// procedure of calculating the data segment size.
type EntryCustomGetDataSegmentSizer interface {
	// CustomGetDataSegmentSize returns the size of the data segment associates with the entry.
	CustomGetDataSegmentSize(firmwareImage io.ReadSeeker) (uint64, error)
}

// CustomRecalculateHeaderser is an extension of Entry which overrides the default
// procedure of recalculating EntryHeaders.
type EntryCustomRecalculateHeaderser interface {
	// CustomRecalculateHeaders recalculates metadata to be consistent with data.
	// For example, it fixes checksum, data size, entry type and so on.
	CustomRecalculateHeaders() error
}

// EntriesByType is a helper to sort a slice of `Entry`-ies by their type/class.
type EntriesByType []Entry

func (entries EntriesByType) Less(i, j int) bool {
	return entries[i].GetEntryBase().Headers.Type() < entries[j].GetEntryBase().Headers.Type()
}
func (entries EntriesByType) Swap(i, j int) { entries[i], entries[j] = entries[j], entries[i] }
func (entries EntriesByType) Len() int      { return len(entries) }

// mostCommonRecalculateHeadersOfEntry recalculates entry headers using headers data using the most common rules:
// * Set "Version" to 0x0100.
// * Set "IsChecksumValid" to true.
// * Set "Type" to the type of the entry.
// * Set "Checksum" to the calculated checksum value of the headers
// * Set "Size" to a multiple of 16 of the data size (in other words: len(data) >> 4).
//
// This is considered the most common set of rules for the most FIT entry types. But different types may break
// different rules.
func mostCommonRecalculateHeadersOfEntry(entry Entry) {
	entryType, foundEntryType := entryTypeOf(entry)
	if !foundEntryType {
		panic(fmt.Errorf("type %T is not known", entry))
	}

	entryBase := entry.GetEntryBase()
	hdr := &entryBase.Headers
	hdr.TypeAndIsChecksumValid.SetType(entryType)
	hdr.TypeAndIsChecksumValid.SetIsChecksumValid(true)
	hdr.Checksum = hdr.CalculateChecksum()
	hdr.Version = EntryVersion(0x0100)
	hdr.Size.SetUint32(uint32(len(entryBase.DataSegmentBytes) >> 4))
}

// EntryRecalculateHeaders recalculates headers of the entry based on its data.
func EntryRecalculateHeaders(entry Entry) error {
	if recalcer, ok := entry.(EntryCustomRecalculateHeaderser); ok {
		return recalcer.CustomRecalculateHeaders()
	}

	mostCommonRecalculateHeadersOfEntry(entry)
	return nil
}

// Entries are a slice of multiple parsed FIT entries (headers + data)
type Entries []Entry

// RecalculateHeaders recalculates metadata to be consistent with data. For example, it fixes checksum, data size,
// entry type and so on.
//
// Supposed to be used before Inject or/and InjectTo. Since it is possible to prepare data in entries, then
// call Rehash (to prepare headers consistent with data).
func (entries Entries) RecalculateHeaders() error {
	if len(entries) == 0 {
		return nil
	}

	for idx, entry := range entries {
		err := EntryRecalculateHeaders(entry)
		if err != nil {
			return fmt.Errorf("unable to recalculate headers of FIT entry #%d (%#+v): %w", idx, entry, err)
		}
	}

	beginEntry, ok := entries[0].(*EntryFITHeaderEntry)
	if !ok {
		return fmt.Errorf("the first entry is not a EntryFITHeaderEntry, but %T", entries[0])
	}

	// See point 4.2.5 of the FIT specification
	beginEntry.GetEntryBase().Headers.Size.SetUint32(uint32(len(entries)))

	return nil
}

// Table returns a table of headers of all entries of the slice.
func (entries Entries) Table() Table {
	result := make(Table, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry.GetEntryBase().Headers)
	}
	return result
}

// Inject writes complete FIT (headers + data + pointer) to a firmware image.
//
// What will happen:
// 1. The FIT headers will be written by offset headersOffset.
// 2. The FIT pointer will be written at consts.FITPointerOffset offset from the end of the image.
// 3. Data referenced by FIT headers will be written at offsets accordingly to Address fields (in the headers).
//
// Consider calling Rehash() before Inject()/InjectTo()
func (entries Entries) Inject(b []byte, headersOffset uint64) error {
	return entries.InjectTo(bytesextra.NewReadWriteSeeker(b), headersOffset)
}

// InjectTo does the same as Inject, but for io.WriteSeeker.
func (entries Entries) InjectTo(w io.WriteSeeker, headersOffset uint64) error {

	// Detect image size

	imageSize, err := w.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("unable to detect the end of the image: %w", err)
	}
	if imageSize < 0 {
		panic(fmt.Errorf("negative image size: %d", imageSize))
	}

	// Write FIT pointer

	if _, err := w.Seek(-consts.FITPointerOffset, io.SeekEnd); err != nil {
		return fmt.Errorf("unable to Seek(%d, %d) to write FIT pointer: %w", headersOffset, io.SeekStart, err)
	}
	pointerValue := calculatePhysAddrFromOffset(headersOffset, uint64(imageSize))
	if err := binary.Write(w, binary.LittleEndian, pointerValue); err != nil {
		return fmt.Errorf("unable to FIT pointer: %w", err)
	}

	// Write headers

	if _, err := w.Seek(int64(headersOffset), io.SeekStart); err != nil {
		return fmt.Errorf("unable to Seek(%d, %d) to write headers: %w", headersOffset, io.SeekStart, err)
	}

	table := entries.Table()
	if _, err := table.WriteTo(w); err != nil {
		return fmt.Errorf("unable to write %d headers to offset %d: %w", len(table), headersOffset, err)
	}

	// Write data sections

	for idx, entry := range entries {
		if err := entry.GetEntryBase().injectDataSectionTo(w); err != nil {
			return fmt.Errorf("unable to inject data section of entry %d: %w", idx, err)
		}
	}

	return nil
}

func copyBytesFrom(r io.ReadSeeker, startIdx, endIdx uint64) ([]byte, error) {
	_, err := r.Seek(int64(startIdx), io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("unable to Seek(%d, io.SeekStart): %w", int64(startIdx), err)
	}

	if endIdx < startIdx {
		return nil, fmt.Errorf("endIdx < startIdx: %d < %d", endIdx, startIdx)
	}

	size := endIdx - startIdx
	result := make([]byte, size)
	written, err := io.CopyN(bytesextra.NewReadWriteSeeker(result), r, int64(size))
	if err != nil {
		return nil, fmt.Errorf("unable to copy %d bytes: %w", int64(size), err)
	}
	if written != int64(size) {
		return nil, fmt.Errorf("invalid amount of bytes copied: %d != %d", written, int64(size))
	}

	return result, nil
}

// EntryDataSegmentSize returns the coordinates of the data segment size associates with the entry.
func EntryDataSegmentSize(entry Entry, firmware io.ReadSeeker) (uint64, error) {
	if sizeGetter, ok := entry.(EntryCustomGetDataSegmentSizer); ok {
		return sizeGetter.CustomGetDataSegmentSize(firmware)
	} else {
		return entry.GetEntryBase().Headers.mostCommonGetDataSegmentSize(), nil
	}
}

// EntryDataSegmentCoordinates returns the coordinates of the data segment coordinates associates with the entry.
func EntryDataSegmentCoordinates(entry Entry, firmware io.ReadSeeker) (uint64, uint64, error) {
	var err error

	offset, addErr := entry.GetEntryBase().Headers.getDataSegmentOffset(firmware)
	if addErr != nil {
		err = multierror.Append(err, fmt.Errorf("unable to get data segment offset: %w", err))
	}

	size, addErr := EntryDataSegmentSize(entry, firmware)
	if addErr != nil {
		err = multierror.Append(err, fmt.Errorf("unable to get data segment size: %w", err))
	}

	return offset, size, err
}

// If possible then make a slice of existing data; if not then copy.
func sliceOrCopyBytesFrom(r io.ReadSeeker, startIdx, endIdx uint64) ([]byte, error) {
	switch r := r.(type) {
	case *bytesextra.ReadWriteSeeker:
		return r.Storage[startIdx:endIdx], nil
	default:
		return copyBytesFrom(r, startIdx, endIdx)
	}
}

func entryInitDataSegmentBytes(entry Entry, firmware io.ReadSeeker) error {
	dataSegmentOffset, dataSegmentSize, err := EntryDataSegmentCoordinates(entry, firmware)
	if err != nil {
		return fmt.Errorf("unable to get data segment coordinates of entry %T: %w", entry, err)
	}

	if dataSegmentSize == 0 {
		return nil
	}

	base := entry.GetEntryBase()

	base.DataSegmentBytes, err = sliceOrCopyBytesFrom(firmware, dataSegmentOffset, dataSegmentOffset+dataSegmentSize)
	if err != nil {
		return fmt.Errorf("unable to copy data segment bytes from the firmware image (offset:%d, size:%d): %w", dataSegmentOffset, dataSegmentSize, err)
	}

	return nil
}

// NewEntry returns a new entry using headers and firmware image
func NewEntry(hdr *EntryHeaders, firmware io.ReadSeeker) Entry {
	entry := hdr.Type().newEntry()
	if entry == nil {
		return nil
	}
	base := entry.GetEntryBase()
	base.Headers = *hdr

	err := entryInitDataSegmentBytes(entry, firmware)
	if err != nil {
		base.HeadersErrors = append(base.HeadersErrors, err)
	}

	return entry
}
