// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"fmt"
	"io"
)

// EntryDiagnosticACM represents a FIT entry of type "Diagnostic ACM" (0x03)
type EntryDiagnosticACM struct{ EntryBase }

var _ EntryCustomGetDataSegmentSizer = (*EntryDiagnosticACM)(nil)

// Init initializes the entry using EntryHeaders and firmware image.
func (entry *EntryDiagnosticACM) CustomGetDataSegmentSize(firmware io.ReadSeeker) (uint64, error) {
	return 0, fmt.Errorf("EntryDiagnosticACM is not supported, yet")
}

var _ EntryCustomRecalculateHeaderser = (*EntryDiagnosticACM)(nil)

// CustomRecalculateHeaders recalculates metadata to be consistent with data.
// For example, it fixes checksum, data size, entry type and so on.
func (entry *EntryDiagnosticACM) CustomRecalculateHeaders() error {
	return fmt.Errorf("EntryDiagnosticACM is not supported, yet")
}
