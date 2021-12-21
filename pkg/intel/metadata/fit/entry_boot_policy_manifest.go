// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"bytes"
	"fmt"

	"github.com/linuxboot/fiano/pkg/intel/metadata/manifest/bootpolicy"
)

// ParseData creates EntryKeyManifestRecord from EntryKeyManifest
func (entry *EntryBootPolicyManifestRecord) ParseData() (*bootpolicy.Manifest, error) {
	var bpManifest bootpolicy.Manifest
	_, err := bpManifest.ReadFrom(bytes.NewReader(entry.GetDataBytes()))
	if err != nil {
		return nil, fmt.Errorf("failed to parse KeyManifest, err: %v", err)
	}
	return &bpManifest, nil
}

// ParseBootPolicyManifest returns a boot policy manifest if it was able to
// parse one.
func (table Table) ParseBootPolicyManifest(firmware []byte) (*bootpolicy.Manifest, error) {
	hdr := table.First(EntryTypeBootPolicyManifest)
	if hdr == nil {
		return nil, ErrNotFound{}
	}

	return hdr.GetEntry(firmware).(*EntryBootPolicyManifestRecord).ParseData()
}
