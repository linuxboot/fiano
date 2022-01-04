// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"encoding/binary"
	"io"
)

// EntryFITHeaderEntry represents a FIT entry of type "FIT Header Entry" (0x00)
type EntryFITHeaderEntry struct{ EntryBase }

var _ EntryCustomGetDataSegmentSizer = (*EntryFITHeaderEntry)(nil)

func (entry *EntryFITHeaderEntry) CustomGetDataSegmentSize(firmware io.ReadSeeker) (uint64, error) {
	// See "1.2.2" of the specification.
	// FITHeaderEntry contains "_FIT_   " string instead of an address.
	// And we shouldn't do anything in this case.
	return 0, nil
}

var _ EntryCustomRecalculateHeaderser = (*EntryFITHeaderEntry)(nil)

func (entry *EntryFITHeaderEntry) CustomRecalculateHeaders() error {
	mostCommonRecalculateHeadersOfEntry(entry)

	// See 4.2 of the FIT specification.
	entry.Headers.Address = Address64(binary.LittleEndian.Uint64([]byte("_FIT_   ")))
	return nil
}
