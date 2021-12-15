// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import "os"

func Open(n string) (*Image, error) {
	f, err := os.Open(n)
	if err != nil {
		return nil, err
	}

	return NewImage(f)
}
