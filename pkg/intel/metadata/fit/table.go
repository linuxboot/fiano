package fit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/9elements/converged-security-suite/v2/pkg/check"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit/consts"
	uefiConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/consts"
)

// Table is the FIT entry headers table (located by the "FIT Pointer")
type Table []EntryHeaders

// GetEntries returns parsed FIT-entries
func (table Table) GetEntries(firmware []byte) (result []Entry) {
	for _, headers := range table {
		result = append(result, headers.GetEntry(firmware))
	}
	return
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
func GetPointerCoordinates(firmware []byte) (startIdx, endIdx uint64) {
	startIdx = uint64(len(firmware)) - consts.FITPointerOffset
	endIdx = startIdx + consts.FITPointerSize
	return
}

// GetHeadersTableRange returns the starting and ending indexes of the FIT
// headers table within the firmware image.
func GetHeadersTableRange(firmware []byte) (startIdx, endIdx uint64, err error) {

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

	fitPointerStartIdx, fitPointerEndIdx := GetPointerCoordinates(firmware)

	if err := check.BytesRange(firmware, int(fitPointerStartIdx), int(fitPointerEndIdx)); err != nil {
		return 0, 0, fmt.Errorf("invalid fit pointer bytes range: %w", err)
	}

	fitPointerBytes := firmware[fitPointerStartIdx:fitPointerEndIdx]
	fitPointerValue := binary.LittleEndian.Uint64(fitPointerBytes)
	fitPointerOffset := uefiConsts.CalculateTailOffsetFromPhysAddr(fitPointerValue)
	startIdx = uint64(len(firmware)) - fitPointerOffset

	// OK, now we need to calculate the end of the headers...
	//
	// It's pretty easy. The first entry describes the table itself, and it's
	// size is the size of the table. So let's just use it.

	firstHeaderEndIdx := startIdx + uint64(entryHeadersSize)
	if err = check.BytesRange(firmware, int(startIdx), int(firstHeaderEndIdx)); err != nil {
		err = fmt.Errorf("invalid the first entry bytes range: %w", err)
		return
	}

	tableMeta := EntryHeaders{}
	err = binary.Read(bytes.NewReader(firmware[int(startIdx):firstHeaderEndIdx]), binary.LittleEndian, &tableMeta)
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
	if bytes.Compare([]byte(consts.FITHeadersMagic), buf.Bytes()) != 0 {
		err = &ErrExpectedFITHeadersMagic{Received: buf.Bytes()}
		return
	}

	// OK, it's correct. Now we know the size of the table and we can
	// parseHeaders it.

	endIdx = startIdx + uint64(tableMeta.Size.Size())
	if err = check.BytesRange(firmware, int(startIdx), int(endIdx)); err != nil {
		err = fmt.Errorf("invalid entries bytes range: %w", err)
		return
	}

	return
}

// GetTable returns the table of FIT entries of the firmware image.
func GetTable(firmware []byte) (Table, error) {
	startIdx, endIdx, err := GetHeadersTableRange(firmware)
	if err != nil {
		return nil, err
	}

	result, err := ParseTable(firmware[startIdx:endIdx])
	if err != nil {
		return nil, err
	}

	return result, nil
}
