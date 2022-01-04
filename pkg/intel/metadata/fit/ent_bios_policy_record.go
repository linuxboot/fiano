// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"io"
)

// EntryBIOSPolicyRecord represents a FIT entry of type "BIOS Policy Record" (0x09)
type EntryBIOSPolicyRecord struct{ EntryBase }

var _ EntryCustomGetDataSegmentSizer = (*EntryBIOSPolicyRecord)(nil)

func (entry *EntryBIOSPolicyRecord) CustomGetDataSegmentSize(firmware io.ReadSeeker) (uint64, error) {
	return uint64(entry.Headers.Size.Uint32()), nil
}

var _ EntryCustomRecalculateHeaderser = (*EntryBIOSPolicyRecord)(nil)

// CustomRecalculateHeaders recalculates metadata to be consistent with data.
// For example, it fixes checksum, data size, entry type and so on.
func (entry *EntryBIOSPolicyRecord) CustomRecalculateHeaders() error {
	mostCommonRecalculateHeadersOfEntry(entry)

	entry.Headers.Size.SetUint32(uint32(len(entry.DataSegmentBytes)))
	return nil
}
