// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !amd64
// +build !amd64

package bytes

// IsZeroFilled returns true if b consists of zeros only.
//
//go:nosplit
func IsZeroFilled(b []byte) bool {
	return isZeroFilledSimple(b)
}
