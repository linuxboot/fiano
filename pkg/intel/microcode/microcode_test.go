// Copyright 2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package microcode

import (
	"bytes"
	"testing"
)

var (
	testMicrocode         = []byte("\x01\x00\x00\x00\x24\x04\x00\x00\x22\x20\x19\x09\xa3\x06\x09\x00\x5d\xd4\xdd\xf6\x01\x00\x00\x00\x80\x00\x00\x00\x04\x00\x00\x00\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	testMicrocodeExtTable = []byte("\x01\x00\x00\x00\x24\x04\x00\x00\x22\x20\x19\x09\xa3\x06\x09\x00\x31\xd4\xdd\xf6\x01\x00\x00\x00\x80\x00\x00\x00\x04\x00\x00\x00\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x06\x5a\x21\x95\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa3\x06\x09\x00\x80\x00\x00\x00\xd9\x4b\x66\xb5\xa4\x06\x09\x00\x80\x00\x00\x00\xd8\x4b\x66\xb5")
)

func TestParseMicrocodeExtTable(t *testing.T) {
	var m *Microcode
	var err error

	if m, err = ParseIntelMicrocode(bytes.NewBuffer(testMicrocodeExtTable)); err != nil {
		t.Errorf("Failed to parse microcode %v", err)
		return
	}
	if m.HeaderProcessorFlags != 0x80 {
		t.Errorf("Got microcode processor flags %#x, expected %#x", m.HeaderProcessorFlags, 0x80)
	}
	if m.HeaderDataSize != 4 {
		t.Errorf("Got microcode data size %#x, expected %#x", m.HeaderDataSize, 4)
	}
	if m.HeaderTotalSize != 0x60 {
		t.Errorf("Got microcode total size %#x, expected %#x", m.HeaderTotalSize, 0x60)
	}
	if m.HeaderProcessorSignature != 0x906a3 {
		t.Errorf("Got microcode processor signature %#x, expected %#x", m.HeaderProcessorSignature, 0x906a3)
	}
	if m.HeaderDate != 0x9192022 {
		t.Errorf("Got microcode date %#x, expected %#x", m.HeaderDate, 0x9192022)
	}
	if len(m.Data) != 4 {
		t.Errorf("Got microcode data length %d, expected %d", len(m.Data), 4)
	}
	if len(m.ExtendedSignatures) != 2 {
		t.Errorf("Got extended signatures %d, expected %d", len(m.ExtendedSignatures), 2)
	}
	if m.ExtendedSignatures[0].ProcessorFlags != 0x80 {
		t.Errorf("Got extended #0 microcode processor flags %#x, expected %#x",
			m.ExtendedSignatures[0].ProcessorFlags, 0x80)
	}
	if m.ExtendedSignatures[0].Signature != 0x906a3 {
		t.Errorf("Got extended #0 processor signature %#x, expected %#x",
			m.ExtendedSignatures[0].Signature, 0x906a3)
	}
	if m.ExtendedSignatures[1].ProcessorFlags != 0x80 {
		t.Errorf("Got extended #1 microcode processor flags %#x, expected %#x",
			m.ExtendedSignatures[1].ProcessorFlags, 0x80)
	}
	if m.ExtendedSignatures[1].Signature != 0x906a4 {
		t.Errorf("Got extended #1 processor signature %#x, expected %#x",
			m.ExtendedSignatures[1].Signature, 0x906a4)
	}
}

func TestParseMicrocode(t *testing.T) {
	var m *Microcode
	var err error

	if m, err = ParseIntelMicrocode(bytes.NewBuffer(testMicrocode)); err != nil {
		t.Errorf("Failed to parse microcode %v", err)
		return
	}
	if m.HeaderProcessorFlags != 0x80 {
		t.Errorf("Got microcode processor flags %#x, expected %#x", m.HeaderProcessorFlags, 0x80)
	}
	if m.HeaderDataSize != 4 {
		t.Errorf("Got microcode data size %#x, expected %#x", m.HeaderDataSize, 4)
	}
	if m.HeaderTotalSize != 0x34 {
		t.Errorf("Got microcode total size %#x, expected %#x", m.HeaderTotalSize, 0x34)
	}
	if m.HeaderProcessorSignature != 0x906a3 {
		t.Errorf("Got microcode processor signature %#x, expected %#x", m.HeaderProcessorSignature, 0x906a3)
	}
	if m.HeaderDate != 0x9192022 {
		t.Errorf("Got microcode date %#x, expected %#x", m.HeaderDate, 0x9192022)
	}
	if len(m.Data) != 4 {
		t.Errorf("Got microcode data length %d, expected %d", len(m.Data), 4)
	}
	if len(m.ExtendedSignatures) != 0 {
		t.Errorf("Got extended signatures %d, expected %d", len(m.ExtendedSignatures), 0)
	}
}

func TestParseMicrocodeErrors(t *testing.T) {
	// Invalid checksum
	testData := make([]byte, len(testMicrocode))
	copy(testData, testMicrocode)
	testData[16] += 1

	if _, err := ParseIntelMicrocode(bytes.NewBuffer(testData)); err == nil {
		t.Errorf("Exptected error but didn't get one")
	}

	// Header version invlaid
	testData = make([]byte, len(testMicrocode))
	copy(testData, testMicrocode)
	testData[0] = 2

	if _, err := ParseIntelMicrocode(bytes.NewBuffer(testData)); err == nil {
		t.Errorf("Exptected error but didn't get one")
	}

	// Datasize not multiple of 4
	testData = make([]byte, len(testMicrocode))
	copy(testData, testMicrocode)
	testData[28] += 1

	if _, err := ParseIntelMicrocode(bytes.NewBuffer(testData)); err == nil {
		t.Errorf("Exptected error but didn't get one")
	}

	// Datasize invalid
	testData = make([]byte, len(testMicrocode))
	copy(testData, testMicrocode)
	testData[28] = 8

	if _, err := ParseIntelMicrocode(bytes.NewBuffer(testData)); err == nil {
		t.Errorf("Exptected error but didn't get one")
	}

	// TotalSize invalid
	testData = make([]byte, len(testMicrocode))
	copy(testData, testMicrocode)
	testData[32] = 0

	if _, err := ParseIntelMicrocode(bytes.NewBuffer(testData)); err == nil {
		t.Errorf("Exptected error but didn't get one")
	}

	// TotalSize invalid
	testData = make([]byte, len(testMicrocode))
	copy(testData, testMicrocode)
	testData[32] += 1

	if _, err := ParseIntelMicrocode(bytes.NewBuffer(testData)); err == nil {
		t.Errorf("Exptected error but didn't get one")
	}

	// ExtTable invalid checksum
	testData = make([]byte, len(testMicrocodeExtTable))
	copy(testData, testMicrocodeExtTable)
	testData[len(testData)-1] += 1

	if _, err := ParseIntelMicrocode(bytes.NewBuffer(testData)); err == nil {
		t.Errorf("Exptected error but didn't get one")
	}

	// Input to short
	for i := 0; i < len(testMicrocodeExtTable)-1; i++ {
		testData = make([]byte, i)
		copy(testData, testMicrocodeExtTable[:i])

		if _, err := ParseIntelMicrocode(bytes.NewBuffer(testData)); err == nil {
			t.Errorf("Exptected error but didn't get one")
		}
	}
}
