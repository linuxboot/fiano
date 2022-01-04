// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"fmt"
)

// GetEntries returns parsed FIT-entries
func GetEntries(firmware []byte) (Entries, error) {
	table, err := GetTable(firmware)
	if err != nil {
		return nil, fmt.Errorf("unable to get FIT table: %w", err)
	}

	return table.GetEntries(firmware), nil
}
