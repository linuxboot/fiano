// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/bg/bgbootpolicy"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntbootpolicy"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/bgheader"
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

// ParseData creates EntryBootPolicyManifestRecord from EntryBootPolicyManifest
func (entry *EntryBootPolicyManifestRecord) ParseData() (*bgbootpolicy.Manifest, *cbntbootpolicy.Manifest, error) {
	r := bytes.NewReader(entry.DataSegmentBytes)
	version, err := bgheader.DetectBGV(r)
	if err != nil {
		return nil, nil, err
	}
	switch version {
	case bgheader.Version10:
		manifest := bgbootpolicy.NewManifest()
		_, err = manifest.ReadFrom(r)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, nil, err
		}
		return manifest, nil, nil
	case bgheader.Version20:
		manifest := cbntbootpolicy.NewManifest()
		_, err = manifest.ReadFrom(r)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, nil, err
		}
		return nil, manifest, nil
	default:
		return nil, nil, fmt.Errorf("failed to parse BootPolicyManifest, err: %v", err)
	}
}

// ParseBootPolicyManifest returns a boot policy manifest if it was able to
// parse one.
func (table Table) ParseBootPolicyManifest(firmware []byte) (*bgbootpolicy.Manifest, *cbntbootpolicy.Manifest, error) {
	hdr := table.First(EntryTypeBootPolicyManifest)
	if hdr == nil {
		return nil, nil, ErrNotFound{}
	}

	return hdr.GetEntry(firmware).(*EntryBootPolicyManifestRecord).ParseData()
}
