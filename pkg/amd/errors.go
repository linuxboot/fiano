package amd

import (
	"fmt"
)

// ErrNotFound describes a situation when particular item is not found
type ErrNotFound struct {
	Item string
}

// Error implements error.
func (err ErrNotFound) Error() string {
	return fmt.Sprintf("'%s' is not found", err.Item)
}
