// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"bytes"
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntkey"
)

// EntryKeyManifestRecord represents a FIT entry of type "Key Manifest Record" (0x0B)
type EntryKeyManifestRecord struct{ EntryBase }

var _ EntryCustomGetDataSegmentSizer = (*EntryKeyManifestRecord)(nil)

func (entry *EntryKeyManifestRecord) CustomGetDataSegmentSize(firmware io.ReadSeeker) (uint64, error) {
	return uint64(entry.Headers.Size.Uint32()), nil
}

var _ EntryCustomRecalculateHeaderser = (*EntryKeyManifestRecord)(nil)

// CustomRecalculateHeaders recalculates metadata to be consistent with data.
// For example, it fixes checksum, data size, entry type and so on.
func (entry *EntryKeyManifestRecord) CustomRecalculateHeaders() error {
	mostCommonRecalculateHeadersOfEntry(entry)

	entry.Headers.Size.SetUint32(uint32(len(entry.DataSegmentBytes)))
	return nil
}

// ParseData creates EntryKeyManifestRecord from EntryKeyManifest
func (entry *EntryKeyManifestRecord) ParseData() (*cbntkey.Manifest, error) {
	var km cbntkey.Manifest
	_, err := km.ReadFrom(bytes.NewReader(entry.DataSegmentBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse KeyManifest, err: %v", err)
	}
	return &km, nil
}

// ParseKeyManifest returns a boot policy manifest if it was able to
// parse one.
func (table Table) ParseKeyManifest(firmware []byte) (*cbntkey.Manifest, error) {
	hdr := table.First(EntryTypeKeyManifestRecord)
	if hdr == nil {
		return nil, ErrNotFound{}
	}

	return hdr.GetEntry(firmware).(*EntryKeyManifestRecord).ParseData()
}
