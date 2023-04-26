// Copyright 2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compression

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"io"
)

const (
	zlibCompressionLevel  = 9
	zlibSectionHeaderSize = 256
	zlibSizeOffset        = 20
)

// ZLIB implements Compressor and uses the zlib package from the standard
// library
type ZLIB struct{}

// Name returns the type of compression employed.
func (c *ZLIB) Name() string {
	return "ZLIB"
}

// Decode decodes a byte slice of ZLIB data.
func (c *ZLIB) Decode(encodedData []byte) ([]byte, error) {
	if len(encodedData) < 256 {
		return nil, errors.New("Zlib.Decode: missing section header")
	}

	// Check size in ZLIB section header
	size := binary.LittleEndian.Uint32(
		encodedData[zlibSizeOffset : zlibSizeOffset+4],
	)
	if size != uint32(len(encodedData)-zlibSectionHeaderSize) {
		return nil, errors.New("ZLIB.Decode: size mismatch")
	}

	// Remove section header
	r, err := zlib.NewReader(
		bytes.NewBuffer(encodedData[zlibSectionHeaderSize:]),
	)
	if err != nil {
		return nil, err
	}

	decodedData, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		return nil, err
	}

	return decodedData, nil
}

// Encode encodes a byte slice with ZLIB.
func (c *ZLIB) Encode(decodedData []byte) ([]byte, error) {
	var encodedData bytes.Buffer

	w, err := zlib.NewWriterLevel(&encodedData, zlibCompressionLevel)
	if err != nil {
		return nil, err
	}

	_, err = w.Write(decodedData)
	w.Close()
	if err != nil {
		return nil, err
	}

	// Add ZLIB section header containing the compressed size and zero padding.
	zlib_header := make([]byte, zlibSectionHeaderSize)
	binary.LittleEndian.PutUint32(
		zlib_header[zlibSizeOffset:],
		uint32(len(encodedData.Bytes())),
	)
	return append(zlib_header, encodedData.Bytes()[:]...), nil
}
