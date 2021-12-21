// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"bytes"
	"fmt"

	"github.com/linuxboot/fiano/pkg/intel/metadata/manifest/key"
)

// ParseData creates EntryKeyManifestRecord from EntryKeyManifest
func (entry *EntryKeyManifestRecord) ParseData() (*key.Manifest, error) {
	var km key.Manifest
	_, err := km.ReadFrom(bytes.NewReader(entry.GetDataBytes()))
	if err != nil {
		return nil, fmt.Errorf("failed to parse KeyManifest, err: %v", err)
	}
	return &km, nil
}

// ParseKeyManifest returns a boot policy manifest if it was able to
// parse one.
func (table Table) ParseKeyManifest(firmware []byte) (*key.Manifest, error) {
	hdr := table.First(EntryTypeKeyManifestRecord)
	if hdr == nil {
		return nil, ErrNotFound{}
	}

	return hdr.GetEntry(firmware).(*EntryKeyManifestRecord).ParseData()
}
