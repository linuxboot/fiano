// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compression

import (
	"bytes"
	"io"

	"github.com/pierrec/lz4"
)

// LZ4 implements Compressor and uses a Go-based implementation.
type LZ4 struct{}

// Name returns the type of compression employed.
func (c *LZ4) Name() string {
	return "LZ4"
}

// Decode decodes a byte slice of LZ4 data.
func (c *LZ4) Decode(encodedData []byte) ([]byte, error) {
	return io.ReadAll(lz4.NewReader(bytes.NewBuffer(encodedData)))
}

// Encode encodes a byte slice with LZ4.
func (c *LZ4) Encode(decodedData []byte) ([]byte, error) {

	buf := bytes.Buffer{}
	w := lz4.NewWriter(&buf)
	_, err := w.Write(decodedData)
	if err != nil {
		return nil, err
	}
	w.Flush()

	return buf.Bytes(), nil
}
