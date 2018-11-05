// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compression

import (
	"bytes"
	"encoding/binary"
	"os/exec"
)

// SystemLZMA implements Compression and calls out to the system's compressor
// (except for Decode which uses the Go-based decompressor). The sytem's
// compressor is typically faster and generates smaller files than the Go-based
// implementation.
type SystemLZMA struct {
	xzPath string
}

// Name returns the type of compression employed.
func (c *SystemLZMA) Name() string {
	return "LZMA"
}

// Decode decodes a byte slice of LZMA data.
func (c *SystemLZMA) Decode(encodedData []byte) ([]byte, error) {
	// When the xz command compresses, it stores an End-Of-Stream (EOS)
	// marker at the end and 0xFFFFFFFFFFFFFFFF in the header. EDK2's
	// decompressor is primitive and will try to allocate
	// 0xFFFFFFFFFFFFFFFF bytes and fail. So, the Encode function writes
	// the size in the header which works for EDK2's tool. Unfortunately,
	// xz considers an lzma file which has both a valid size and EOS corrupt,
	// but will still decompress it and return exit status 1 (false
	// positive). We simply use the Go decompressor despite being slow.
	return (&LZMA{}).Decode(encodedData)
}

// Encode encodes a byte slice with LZMA.
func (c *SystemLZMA) Encode(decodedData []byte) ([]byte, error) {
	cmd := exec.Command(c.xzPath, "--format=lzma", "-7", "--stdout")
	cmd.Stdin = bytes.NewBuffer(decodedData)
	encodedData, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Quoting the XZ Utils manpage:
	//
	//     xz supports decompressing .lzma files with or without
	//     end-of-payload marker, but all .lzma files created by xz will
	//     use end-of-payload marker and have uncompressed size marked as
	//     unknown in the .lzma header. This may be a problem in some
	//     uncommon situations. For example, a .lzma decompressor in an
	//     embedded device might work only with files that have known
	//     uncompressed size.
	//
	// This also affects some UEFI implementations, so the size must be
	// written to the header.
	buf := &bytes.Buffer{}
	if err := binary.Write(buf, binary.LittleEndian, uint64(len(decodedData))); err != nil {
		return nil, err
	}
	copy(encodedData[5:5+8], buf.Bytes())
	return encodedData, nil
}
