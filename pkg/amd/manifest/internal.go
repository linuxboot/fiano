// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package manifest

import (
	"encoding/binary"
	"io"
)

func readAndCountSize(r io.Reader, order binary.ByteOrder, data interface{}, counter *uint64) error {
	if err := binary.Read(r, order, data); err != nil {
		return err
	}
	if counter != nil {
		*counter += uint64(binary.Size(data))
	}
	return nil
}
