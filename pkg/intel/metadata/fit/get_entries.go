package fit

import (
	"fmt"
)

// GetEntries returns parsed FIT-entries
func GetEntries(firmware []byte) ([]Entry, error) {
	table, err := GetTable(firmware)
	if err != nil {
		return nil, fmt.Errorf("unable to get FIT table: %w", err)
	}

	return table.GetEntries(firmware), nil
}
