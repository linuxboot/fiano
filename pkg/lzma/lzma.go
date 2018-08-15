// Package lzma implements reading and writing of LZMA compressed files.
//
// This package is specifically designed for the LZMA format used popular UEFI
// implementations. It requires the `lzma` and `unlzma` programs to be
// installed and on the path.
package lzma

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// LZMA configures the LZMA binary to use.
type LZMA struct {
	Encoder, Decoder string
}

// Default uses whichever commands are in $PATH.
var Default = LZMA{
	Encoder: "lzma",
	Decoder: "unlzma",
}

// Decode decodes a byte slice of LZMA data.
func (l LZMA) Decode(encodedData []byte) ([]byte, error) {
	cmd := exec.Command(l.Decoder)
	cmd.Stdin = bytes.NewBuffer(encodedData)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

// Encode encodes a byte slice with LZMA.
func (l LZMA) Encode(decodedData []byte) ([]byte, error) {
	return l.EncodeLevel(decodedData, 6)
}

// EncodeLevel encodes a byte slice with LZMA. `level` is a value in the range
// 0..9 where 9 gives the best compression.
func (l LZMA) EncodeLevel(decodedData []byte, level int) ([]byte, error) {
	if level < 0 || 9 < level {
		return nil, errors.New("lzma level must be in range 0..9")
	}
	args := append([]string{"--single-stream"}, fmt.Sprintf("-%d", level))

	cmd := exec.Command(l.Encoder, args...)
	cmd.Stdin = bytes.NewBuffer(decodedData)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}
