// Copyright 2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package microcode

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	DefaultDatasize  = 2000
	DefaultTotalSize = 2048
)

type Microcode struct {
	Header
	Data               []byte
	ExtSigTable        ExtendedSigTable
	ExtendedSignatures []ExtendedSignature
}

func (m *Microcode) String() string {
	s := fmt.Sprintf("sig=0x%x, pf=0x%x, rev=0x%x, total size=0x%x, date = %04x-%02x-%02x",
		m.HeaderProcessorSignature, m.HeaderProcessorFlags, m.HeaderRevision,
		getTotalSize(m.Header), m.HeaderDate&0xffff, m.HeaderDate>>24, (m.HeaderDate>>16)&0xff)
	if len(m.ExtendedSignatures) > 0 {
		s += "\n"
	}
	for i := range m.ExtendedSignatures {
		s += fmt.Sprintf("Extended signature[%d]: %s\n", i, m.ExtendedSignatures[i].String())
	}
	return s
}

type Header struct {
	HeaderVersion            uint32 // must be 0x1
	HeaderRevision           uint32
	HeaderDate               uint32 // packed BCD, MMDDYYYY
	HeaderProcessorSignature uint32
	HeaderChecksum           uint32
	HeaderLoaderRevision     uint32
	HeaderProcessorFlags     uint32
	HeaderDataSize           uint32 // 0 means 2000
	HeaderTotalSize          uint32 // 0 means 2048
	Reserved1                [3]uint32
}

type ExtendedSignature struct {
	Signature      uint32
	ProcessorFlags uint32
	Checksum       uint32
}

func (e *ExtendedSignature) String() string {
	return fmt.Sprintf("sig=0x%x, pf=0x%x", e.Signature, e.ProcessorFlags)
}

type ExtendedSigTable struct {
	Count    uint32
	Checksum uint32
	Reserved [3]uint32
}

func getTotalSize(h Header) uint32 {
	if h.HeaderDataSize > 0 {
		return h.HeaderTotalSize
	} else {
		return DefaultTotalSize
	}
}

func getDataSize(h Header) uint32 {
	if h.HeaderDataSize > 0 {
		return h.HeaderDataSize
	} else {
		return DefaultDatasize
	}
}

// ParseIntelMicrocode parses the Intel microcode update
func ParseIntelMicrocode(r io.Reader) (*Microcode, error) {
	var m Microcode

	if err := binary.Read(r, binary.LittleEndian, &m.Header); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Sanitychecks
	if getTotalSize(m.Header) < getDataSize(m.Header)+uint32(binary.Size(Header{})) {
		return nil, fmt.Errorf("bad data file size")
	}
	if m.HeaderLoaderRevision != 1 || m.HeaderVersion != 1 {
		return nil, fmt.Errorf("invalid version or revision")
	}
	if getDataSize(m.Header)%4 > 0 {
		return nil, fmt.Errorf("data size not 32bit aligned")
	}
	if getTotalSize(m.Header)%4 > 0 {
		return nil, fmt.Errorf("total size not 32bit aligned")
	}
	// Read data
	m.Data = make([]byte, getDataSize(m.Header))
	if err := binary.Read(r, binary.LittleEndian, &m.Data); err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	// Calculcate checksum
	buf := bytes.NewBuffer([]byte{})
	buf.Grow(int(getDataSize(m.Header)) + binary.Size(Header{}))
	_ = binary.Write(buf, binary.LittleEndian, &m.Header)
	_ = binary.Write(buf, binary.LittleEndian, &m.Data)

	var checksum uint32
	for {
		var data uint32
		if err := binary.Read(buf, binary.LittleEndian, &data); err != nil {
			break
		}
		checksum += data
	}
	if checksum != 0 {
		return nil, fmt.Errorf("checksum is not null: %#x", checksum)
	}

	if getTotalSize(m.Header) <= getDataSize(m.Header)+uint32(binary.Size(Header{})) {
		return &m, nil
	}

	// Read extended header
	if err := binary.Read(r, binary.LittleEndian, &m.ExtSigTable); err != nil {
		return nil, fmt.Errorf("failed to read extended sig table: %w", err)
	}
	for i := uint32(0); i < m.ExtSigTable.Count; i++ {
		var signature ExtendedSignature
		if err := binary.Read(r, binary.LittleEndian, &signature); err != nil {
			return nil, fmt.Errorf("failed to read extended signature: %w", err)
		}
		m.ExtendedSignatures = append(m.ExtendedSignatures, signature)
	}

	// Calculcate checksum
	buf = bytes.NewBuffer([]byte{})
	buf.Grow(binary.Size(ExtendedSigTable{}) +
		int(m.ExtSigTable.Count)*binary.Size(ExtendedSignature{}))
	_ = binary.Write(buf, binary.LittleEndian, &m.ExtSigTable)
	for i := uint32(0); i < m.ExtSigTable.Count; i++ {
		_ = binary.Write(buf, binary.LittleEndian, &m.ExtendedSignatures[i])
	}

	checksum = 0
	for {
		var data uint32
		if err := binary.Read(buf, binary.LittleEndian, &data); err != nil {
			break
		}
		checksum += data
	}
	if checksum != 0 {
		return nil, fmt.Errorf("extended header checksum is not null: %#x", checksum)
	}

	return &m, nil
}
