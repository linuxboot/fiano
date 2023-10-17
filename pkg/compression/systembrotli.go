// Copyright 2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compression

import (
	"bytes"
	"encoding/binary"
	"os/exec"
)

// SystemBROTLI implements Compression and calls out to the system's compressor
type SystemBROTLI struct {
	brotliPath string
}

// Name returns the type of compression employed.
func (c *SystemBROTLI) Name() string {
	return "BROTLI"
}

// Decode decodes a byte slice of BROTLI data.
func (c *SystemBROTLI) Decode(encodedData []byte) ([]byte, error) {
	// The start of the brotli section contains an 8 byte header describing
	// the final uncompressed size. The real data starts at 0x10

	cmd := exec.Command(c.brotliPath, "--stdout", "-d")
	cmd.Stdin = bytes.NewBuffer(encodedData[0x10:])

	decodedData, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return decodedData, nil
}

// Encode encodes a byte slice with BROTLI.
func (c *SystemBROTLI) Encode(decodedData []byte) ([]byte, error) {
	cmd := exec.Command(c.brotliPath, "--stdout", "-q", "9")
	cmd.Stdin = bytes.NewBuffer(decodedData)

	encodedData, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Generate the size of the decoded data for the header
	decodedSize := &bytes.Buffer{}
	if err := binary.Write(decodedSize, binary.LittleEndian, uint64(len(decodedData))); err != nil {
		return nil, err
	}

	// This seems to be the buffer size needed by the UEFI decompressor
	// 0x03000000 should suffice. The EDK2 base tools generates this header
	// using Brotli internals. This needs to be tuned somehow
	scratchBufferSize := []byte{0x00, 0x00, 0x00, 0x03, 0, 0, 0, 0}
	header := append(decodedSize.Bytes(), scratchBufferSize...)

	encodedData = append(header, encodedData...)

	return encodedData, nil
}
