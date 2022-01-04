// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"fmt"
	"io"
)

// EntryBase is the common information for any FIT entry
type EntryBase struct {
	// Headers is FIT entry headers.
	//
	// See "Table 1-1" in "1.2 Firmware Interface Table" in "Firmware Interface Table" specification:
	//  * https://www.intel.com/content/dam/www/public/us/en/documents/guides/fit-bios-specification.pdf
	Headers EntryHeaders

	// DataSegmentBytes is the raw bytes of the special data segment referenced by the headers.
	//
	// Is not nil only if FIT entry really references to a data segment. If FIT entry
	// stores data directly in headers then DataSegmentBytes is nil.
	DataSegmentBytes []byte `json:",omitempty"`

	// HeadersErrors is the list of errors occurred while parsing and interpreting FIT entry headers.
	HeadersErrors []error `json:",omitempty"`
}

// GetEntryBase returns EntryBase (which contains metadata of the Entry).
func (entry *EntryBase) GetEntryBase() *EntryBase {
	return entry
}

// GoString implements fmt.GoStringer
func (entry *EntryBase) GoString() string {
	return entry.Headers.GoString()
}

// injectDataSectionTo does the same as InjectData, but for io.WriteSeeker.
func (entry EntryBase) injectDataSectionTo(w io.WriteSeeker) error {
	base := entry.GetEntryBase()

	if len(base.DataSegmentBytes) == 0 {
		return nil
	}

	firmwareSize, err := w.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("unable to detect firmware size: %w", err)
	}

	dataSectionOffset := base.Headers.Address.Offset(uint64(firmwareSize))
	if _, err := w.Seek(int64(dataSectionOffset), io.SeekStart); err != nil {
		return fmt.Errorf("unable to Seek(%d, %d) to write the data section: %w", int64(dataSectionOffset), io.SeekStart, err)
	}

	if _, err := w.Write(entry.DataSegmentBytes); err != nil {
		return fmt.Errorf("unable to write the data section: %w", err)
	}

	return nil
}
