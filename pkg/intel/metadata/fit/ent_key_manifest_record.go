// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/bg/bgkey"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntkey"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/bgheader"
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

// Reader creates io.ReadSeeker from EntryKeyManifestRecord
func (entry *EntryKeyManifestRecord) Reader() *bytes.Reader {
	return bytes.NewReader(entry.DataSegmentBytes)
}

// ParseData creates EntryKeyManifestRecord from EntryKeyManifest
func (entry *EntryKeyManifestRecord) ParseData() (*bgkey.Manifest, *cbntkey.Manifest, error) {
	r := bytes.NewReader(entry.DataSegmentBytes)
	version, err := bgheader.DetectBGV(r)
	if err != nil {
		return nil, nil, err
	}
	switch version {
	case bgheader.Version10:
		manifest := bgkey.NewManifest()
		_, err = manifest.ReadFrom(r)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, nil, err
		}
		return manifest, nil, nil
	case bgheader.Version20:
		manifest := cbntkey.NewManifest()
		_, err = manifest.ReadFrom(r)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, nil, err
		}
		return nil, manifest, nil
	default:
		return nil, nil, fmt.Errorf("failed to parse KeyManifest, err: %v", err)
	}
}

// ParseKeyManifest returns a key manifest if it was able to
// parse one.
func (table Table) ParseKeyManifest(firmware []byte) (*bgkey.Manifest, *cbntkey.Manifest, error) {
	hdr := table.First(EntryTypeBootPolicyManifest)
	if hdr == nil {
		return nil, nil, ErrNotFound{}
	}

	return hdr.GetEntry(firmware).(*EntryKeyManifestRecord).ParseData()
}
