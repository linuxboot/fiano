// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"bytes"
	"io"
)

// EntryBootPolicyManifestRecord represents a FIT entry of type "Boot Policy Manifest" (0x0C)
type EntryBootPolicyManifestRecord struct{ EntryBase }

var _ EntryCustomGetDataSegmentSizer = (*EntryBootPolicyManifestRecord)(nil)

func (entry *EntryBootPolicyManifestRecord) CustomGetDataSegmentSize(firmware io.ReadSeeker) (uint64, error) {
	return uint64(entry.Headers.Size.Uint32()), nil
}

var _ EntryCustomRecalculateHeaderser = (*EntryBootPolicyManifestRecord)(nil)

// CustomRecalculateHeaders recalculates metadata to be consistent with data.
// For example, it fixes checksum, data size, entry type and so on.
func (entry *EntryBootPolicyManifestRecord) CustomRecalculateHeaders() error {
	mostCommonRecalculateHeadersOfEntry(entry)

	entry.Headers.Size.SetUint32(uint32(len(entry.DataSegmentBytes)))
	return nil
}

// Reader creates io.ReadSeeker from EntryBootPolicyManifestRecord
func (entry *EntryBootPolicyManifestRecord) Reader() *bytes.Reader {
	return bytes.NewReader(entry.DataSegmentBytes)
}
