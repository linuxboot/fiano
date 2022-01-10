// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package check

import (
	"github.com/hashicorp/go-multierror"
)

func bounds(length uint, startIdx, endIdx int) error {
	var result *multierror.Error
	if startIdx < 0 {
		result = multierror.Append(result, &ErrStartLessThanZero{StartIdx: startIdx})
	}
	if endIdx < startIdx {
		result = multierror.Append(result, &ErrEndLessThanStart{StartIdx: startIdx, EndIdx: endIdx})
	}
	if endIdx >= 0 && uint(endIdx) > length {
		result = multierror.Append(result, &ErrEndGreaterThanLength{Length: length, EndIdx: endIdx})
	}

	return result.ErrorOrNil()
}

// BytesRange checks if starting index `startIdx`, ending index `endIdx` and
// len(b) passes sanity checks:
// * 0 <= startIdx
// * startIdx <= endIdx
// * endIdx < len(b)
func BytesRange(length uint, startIdx, endIdx int) error {
	return bounds(length, startIdx, endIdx)
}
