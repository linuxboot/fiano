// Copyright 2017-2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bgheader

import (
	"encoding/binary"
	"fmt"
	"io"
)

var (
	binaryOrder = binary.LittleEndian
)

type structInfo struct {
	ID      structureID `json:"StructInfoID"`
	Version uint8       `json:"StructInfoVersion"`
}

type structureID [8]byte

type BootGuardVersion uint8

const (
	Version10 BootGuardVersion = 1
	Version20 BootGuardVersion = 2
)

func (bgv BootGuardVersion) String() string {
	switch bgv {
	case Version10:
		return "1.0"
	case Version20:
		return "2.0"
	}
	return "unknown"
}

func DetectBGV(r io.Reader) (BootGuardVersion, error) {
	var s structInfo
	err := binary.Read(r, binaryOrder, &s)
	if err != nil {
		return 0, fmt.Errorf("unable to read field 'ID': %w", err)
	}
	if s.Version >= 0x20 {
		return Version20, nil
	} else if (s.Version < 0x20) && (s.Version >= 0x10) {
		return Version10, nil
	} else {
		return 0, fmt.Errorf("couldn't detect version")
	}
}
