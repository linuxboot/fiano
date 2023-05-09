// Copyright 2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package psb

import (
	"fmt"
)

func reverse(s []byte) []byte {
	if s == nil || len(s) == 0 {
		return nil
	}
	d := make([]byte, len(s))
	copy(d, s)

	for right := len(d)/2 - 1; right >= 0; right-- {
		left := len(d) - 1 - right
		d[right], d[left] = d[left], d[right]
	}
	return d
}

func checkBoundaries(start, end uint64, blob []byte) error {
	if start > uint64(len(blob)) {
		return fmt.Errorf("boundary check error: start is beyond blob bondary (%d > %d)", start, len(blob))
	}
	if end > uint64(len(blob)) {
		return fmt.Errorf("boundary check error: start is beyond blob bondary (%d > %d)", end, len(blob))
	}
	if start > end {
		return fmt.Errorf("boundary check error: start > end (%d > %d)", start, end)
	}
	return nil
}
