// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/fit/check"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit/consts"
	"github.com/xaionaro-go/bytesextra"
)

// Table is the FIT entry headers table (located by the "FIT Pointer"), without
// data this headers reference to.
type Table []EntryHeaders

// GetEntries returns parsed FIT-entries
func (table Table) GetEntries(firmware []byte) (result Entries) {
	return table.GetEntriesFrom(bytesextra.NewReadWriteSeeker(firmware))
}

// GetEntriesFrom returns parsed FIT-entries
func (table Table) GetEntriesFrom(firmware io.ReadSeeker) (result Entries) {
	for _, headers := range table {
		result = append(result, headers.GetEntryFrom(firmware))
	}
	return
}

// String prints the fit table in a tabular form
func (table Table) String() string {
	var s strings.Builder
	// PrintFit prints the Firmware Interface Table in a tabular human readable form.
	fmt.Fprintf(&s, "%-3s | %-32s | %-20s | %-8s | %-6s | %-15s | %-10s\n", "#", "Type", "Address", "Size", "Version", "Checksum valid", "Checksum")
	s.WriteString("---------------------------------------------------------------------------------------------------------------\n")
	for idx, entry := range table {
		fmt.Fprintf(&s, "%-3d | %-25s (0x%02X) | %-20s | %-8d | 0x%04x  | %-15v | %-10d\n",
			idx,
			entry.Type(), uint8(entry.Type()),
			entry.Address.String(),
			entry.Size.Uint32(),
			uint16(entry.Version),
			entry.IsChecksumValid(),
			entry.Checksum)
	}
	return s.String()
}

// First returns the first entry headers with selected entry type
func (table Table) First(entryType EntryType) *EntryHeaders {
	for idx, headers := range table {
		if headers.Type() == entryType {
			return &table[idx]
		}
	}
	return nil
}

// Write compiles FIT headers into a binary representation and writes to "b". If len(b)
// is less than required, then io.ErrUnexpectedEOF is returned.
func (table Table) Write(b []byte) (n int, err error) {
	for idx, entryHeaders := range table {
		addN, err := entryHeaders.Write(b)
		if err != nil {
			return n, fmt.Errorf("unable to write headers #%d (%#+v): %w", idx, entryHeaders, err)
		}
		n += addN
	}

	return n, nil
}

// WriteTo does the same as Write, but for io.Writer
func (table Table) WriteTo(w io.Writer) (n int64, err error) {
	for idx, entryHeaders := range table {
		addN, err := entryHeaders.WriteTo(w)
		if err != nil {
			return n, fmt.Errorf("unable to write headers #%d (%#+v): %w", idx, entryHeaders, err)
		}
		n += addN
	}

	return n, nil
}

// WriteToFirmwareImage finds the position of FIT in a firmware image and writes the table there.
func (table Table) WriteToFirmwareImage(w io.ReadWriteSeeker) (n int64, err error) {
	startIdx, _, err := GetHeadersTableRangeFrom(w)
	if err != nil {
		return 0, fmt.Errorf("unable to find the beginning of the FIT: %w", err)
	}

	if _, err := w.Seek(int64(startIdx), io.SeekStart); err != nil {
		return 0, fmt.Errorf("unable to Seek(%d, io.SeekStart): %w", int64(startIdx), err)
	}

	return table.WriteTo(w)
}

// ParseEntryHeadersFrom parses a single entry headers entry.
func ParseEntryHeadersFrom(r io.Reader) (*EntryHeaders, error) {
	entryHeaders := EntryHeaders{}
	err := binary.Read(r, binary.LittleEndian, &entryHeaders)
	if err != nil {
		return nil, fmt.Errorf("unable to parse FIT entry headers: %w", err)
	}

	return &entryHeaders, nil
}

// ParseTable parses a FIT table from `b`.
func ParseTable(b []byte) (Table, error) {
	var result Table
	r := bytes.NewReader(b)
	for r.Len() > 0 {
		entryHeaders, err := ParseEntryHeadersFrom(r)
		if err != nil {
			return nil, fmt.Errorf("unable to parse FIT headers table: %w", err)
		}
		result = append(result, *entryHeaders)
	}
	return result, nil
}

// GetPointerCoordinates returns the position of the FIT pointer within
// the firmware.
func GetPointerCoordinates(firmwareSize uint64) (startIdx, endIdx int64) {
	startIdx = int64(firmwareSize) - consts.FITPointerOffset
	endIdx = startIdx + consts.FITPointerSize
	return
}

// GetHeadersTableRangeFrom returns the starting and ending indexes of the FIT
// headers table within the firmware image.
func GetHeadersTableRangeFrom(firmware io.ReadSeeker) (startIdx, endIdx uint64, err error) {

	/*
		An example:
		<image start>
		...
		01bb0000: 5f46 4954 5f20 2020 1b00 0000 0001 0000  _FIT_   ........ <--+
		01bb0010: 80d5 e3ff 0000 0000 0000 0000 0001 0100  ................    |
		01bb0020: 804d e4ff 0000 0000 0000 0000 0001 0100  .M..............    |
		01bb0030: 80c5 e4ff 0000 0000 0000 0000 0001 0100  ................    |
		01bb0040: 8035 e5ff 0000 0000 0000 0000 0001 0100  .5..............    |
		01bb0050: ffff ffff 0000 0000 0000 0000 0001 7f00  ................    |
		...                                                                    |
		01bb0180: 7000 7100 0105 2a00 0000 0000 0000 0a00  p.q...*.........    |
		01bb0190: 80c2 e5ff 0000 0000 4102 0000 0001 0b00  ........A.......    |
		01bb01a0: 00b2 e5ff 0000 0000 df02 0000 0001 0c00  ................    |
		01bb01b0: xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  xxxxxxxxxxxxxxxx    |
		...                                                                    |
		01ffffb0: xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  xxxxxxxxxxxxxxxx    |
		01ffffc0: 0000 bbff 0000 0000 0000 0000 0000 0000  ................ >--+
		01ffffd0: xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  xxxxxxxxxxxxxxxx
		01ffffe0: xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  xxxxxxxxxxxxxxxx
		01fffff0: xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  xxxxxxxxxxxxxxxx
		<image end>

		So "0000 bbff" (LE: 0xffbb0000) is seems to be the fitPointer
		(according to the specification).

		Re-check:
		 * fitPointerOffset <- 0x100000000 - 0xffbb0000 == 0x450000
		 * headersStartIdx <- 0x2000000 - 0x450000 == 0x1bb0000
		It's the correct value, yey!

		The full procedure in more formal terms was:
		 * fitPointerPointer <- 0x2000000 (firmwareLength) - 0x40 == 0x01ffffc0
		 * fitPointer <- *fitPointerPointer == 0xffbb0000
		 * fitPointerOffset <- 0x100000000 (const) - 0xffbb0000 == 0x450000
		 * headersStartIdx <- 0x2000000 - 0x450000 == 0x1bb0000
	*/

	firmwareSize, err := firmware.Seek(0, io.SeekEnd)
	if err != nil || firmwareSize < 0 {
		return 0, 0, fmt.Errorf("unable to determine firmware size; result: %d; err: %w", firmwareSize, err)
	}

	fitPointerStartIdx, fitPointerEndIdx := GetPointerCoordinates(uint64(firmwareSize))

	if err := check.BytesRange(uint(firmwareSize), int(fitPointerStartIdx), int(fitPointerEndIdx)); err != nil {
		return 0, 0, fmt.Errorf("invalid fit pointer bytes range: %w", err)
	}

	fitPointerBytes, err := sliceOrCopyBytesFrom(firmware, uint64(fitPointerStartIdx), uint64(fitPointerEndIdx))
	if err != nil {
		return 0, 0, fmt.Errorf("unable to get FIT pointer value: %w", err)
	}
	fitPointerValue := binary.LittleEndian.Uint64(fitPointerBytes)
	fitPointerOffset := CalculateTailOffsetFromPhysAddr(fitPointerValue)
	startIdx = uint64(firmwareSize) - fitPointerOffset

	// OK, now we need to calculate the end of the headers...
	//
	// It's pretty easy. The first entry describes the table itself, and it's
	// size is the size of the table. So let's just use it.

	firstHeaderEndIdx := startIdx + uint64(entryHeadersSize)
	if err = check.BytesRange(uint(firmwareSize), int(startIdx), int(firstHeaderEndIdx)); err != nil {
		err = fmt.Errorf("invalid the first entry bytes range: %w", err)
		return
	}

	tableMeta := EntryHeaders{}

	if _, err = firmware.Seek(int64(startIdx), io.SeekStart); err != nil {
		err = fmt.Errorf("unable to Seek(%d, io.SeekStart) in the firmware: %w", int64(startIdx), err)
		return
	}
	err = binary.Read(firmware, binary.LittleEndian, &tableMeta)
	if err != nil {
		err = fmt.Errorf("unable to parse the first entry: %w", err)
		return
	}

	// Verify if the first entry contains "_FIT_  " as the address (as it is
	// described by the point 1.2.2 of the specification).

	var buf bytes.Buffer
	err = binary.Write(&buf, binary.LittleEndian, tableMeta.Address)
	if err != nil {
		err = fmt.Errorf("unable to read the Address value of the FIT header entry: %w", err)
		return
	}
	if !bytes.Equal([]byte(consts.FITHeadersMagic), buf.Bytes()) {
		err = &ErrExpectedFITHeadersMagic{Received: buf.Bytes()}
		return
	}

	// OK, it's correct. Now we know the size of the table and we can
	// parseHeaders it.

	endIdx = startIdx + uint64(tableMeta.Size.Uint32()<<4) // See 4.2.5
	if err = check.BytesRange(uint(firmwareSize), int(startIdx), int(endIdx)); err != nil {
		err = fmt.Errorf("invalid entries bytes range: %w", err)
		return
	}

	return
}

// GetTable returns the table of FIT entries of the firmware image.
func GetTable(firmware []byte) (Table, error) {
	return GetTableFrom(bytesextra.NewReadWriteSeeker(firmware))
}

// GetTableFrom returns the table of FIT entries of the firmware image.
func GetTableFrom(firmware io.ReadSeeker) (Table, error) {
	startIdx, endIdx, err := GetHeadersTableRangeFrom(firmware)
	if err != nil {
		return nil, fmt.Errorf("unable to locate the table coordinates (does the image contain FIT?): %w", err)
	}

	tableBytes, err := sliceOrCopyBytesFrom(firmware, startIdx, endIdx)
	if err != nil {
		return nil, fmt.Errorf("unable to copy bytes from the firmware: %w", err)
	}

	result, err := ParseTable(tableBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse the table: %w", err)
	}

	return result, nil
}
