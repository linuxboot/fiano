// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"fmt"
	"io"
)

// EntryTPMPolicyRecord represents a FIT entry of type "TPM Policy Record" (0x08)
type EntryTPMPolicyRecord struct{ EntryBase }

var _ EntryCustomGetDataSegmentSizer = (*EntryTPMPolicyRecord)(nil)

// Init initializes the entry using EntryHeaders and firmware image.
func (entry *EntryTPMPolicyRecord) CustomGetDataSegmentSize(firmware io.ReadSeeker) (uint64, error) {
	return 0, fmt.Errorf("EntryTPMPolicyRecord is not supported, yet")
}

var _ EntryCustomRecalculateHeaderser = (*EntryTPMPolicyRecord)(nil)

// CustomRecalculateHeaders recalculates metadata to be consistent with data.
// For example, it fixes checksum, data size, entry type and so on.
func (entry *EntryTPMPolicyRecord) CustomRecalculateHeaders() error {
	return fmt.Errorf("EntryTPMPolicyRecord is not supported, yet")
}
