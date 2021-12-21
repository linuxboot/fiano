// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package check

import (
	"fmt"
)

// ErrStartLessThanZero means `startIdx` has negative value
type ErrStartLessThanZero struct {
	StartIdx int
}

func (err *ErrStartLessThanZero) Error() string {
	return fmt.Sprintf("start index is less than zero: %d", err.StartIdx)
}

// ErrEndLessThanStart means `endIdx` value is less than `startIdx` value
type ErrEndLessThanStart struct {
	StartIdx int
	EndIdx   int
}

func (err *ErrEndLessThanStart) Error() string {
	return fmt.Sprintf("end index is less than start index: %d < %d",
		err.EndIdx, err.StartIdx)
}

// ErrEndGreaterThanLength means `endIdx` is greater or equal to the length.
type ErrEndGreaterThanLength struct {
	Length uint
	EndIdx int
}

func (err *ErrEndGreaterThanLength) Error() string {
	return fmt.Sprintf("end index is outside of the bounds: %d >= %d",
		err.EndIdx, err.Length)
}
