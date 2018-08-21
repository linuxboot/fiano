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

	_ "github.com/ulikunitz/xz/lzma"
)

const (
	lzmaEncode = "lzma"
	lzmaDecode = "unlzma"
)

// Decode decodes a byte slice of LZMA data.
func Decode(encodedData []byte) ([]byte, error) {
	cmd := exec.Command(lzmaDecode)
	cmd.Stdin = bytes.NewBuffer(encodedData)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

// Encode encodes a byte slice with LZMA.
func Encode(decodedData []byte) ([]byte, error) {
	return EncodeLevel(decodedData, 6)
}

// EncodeLevel encodes a byte slice with LZMA. `level` is a value in the range
// 0..9 where 9 gives the best compression.
func EncodeLevel(decodedData []byte, level int) ([]byte, error) {
	if level < 0 || 9 < level {
		return nil, errors.New("lzma level must be in range 0..9")
	}
	args := append([]string{"--single-stream"}, fmt.Sprintf("-%d", level))

	cmd := exec.Command(lzmaEncode, args...)
	cmd.Stdin = bytes.NewBuffer(decodedData)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}
