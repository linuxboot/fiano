// Package lzma implements reading and writing of LZMA compressed files.
//
// This package is specifically designed for the LZMA format used popular UEFI
// implementations. It requires the `lzma` and `unlzma` programs to be
// installed and on the path.
package lzma

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
)

// LZMA configures the LZMA binary to use.
type LZMA struct {
	XZPath string
}

// Default uses whichever commands are in $PATH.
//
// Using the xz tool for LZMA may seem a bit bizarre at first, but xz is
// backwards compatible with lzma (assume the --format=lzma flag is used). And,
// on many distros, lzma points to xz. XZ is the new LZMA.
var Default = LZMA{
	XZPath: "xz",
}

// Decode decodes a byte slice of LZMA data.
func (l LZMA) Decode(encodedData []byte) ([]byte, error) {
	args := []string{
		"--format=lzma",
		"--decompress",
		"--stdout",
	}
	cmd := exec.Command(l.XZPath, args...)
	cmd.Stdin = bytes.NewBuffer(encodedData)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err == nil {
		return out, nil
	}

	// TODO: This is extremely hacky. This reverses the damage we inflicted
	// on the compressed lzma file in EncodeLevel.
	copy(encodedData[5:5+8], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	cmd = exec.Command(l.XZPath, args...)
	cmd.Stdin = bytes.NewBuffer(encodedData)
	if cmd.Run() == nil {
		log.Print("the corruption was a false positive")
		return out, nil
	}
	return nil, err
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
	args := []string{
		"--format=lzma",
		"--compress",
		"--stdout",
		fmt.Sprintf("-%d", level),
	}

	cmd := exec.Command(l.XZPath, args...)
	cmd.Stdin = bytes.NewBuffer(decodedData)
	cmd.Stderr = os.Stderr
	encodedData, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Quoting the XZ Utils manpage:
	//
	//     xz supports decompressing .lzma files with or without
	//     end-of-payload marker, but all.lzma files created by xz will use
	//     end-of-payload marker and have uncompressed size marked as
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
