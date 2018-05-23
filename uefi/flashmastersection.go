package uefi

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// FlashMasterSectionSize is the size in bytes of the FlashMaster section
const FlashMasterSectionSize = 12

// FlashMasterSection holds all the IDs and read/write permissions for other regions
// This controls whether the bios region can read/write to the ME for example.
type FlashMasterSection struct {
	BiosID    uint16
	BiosRead  uint8
	BiosWrite uint8
	MeID      uint16
	MeRead    uint8
	MeWrite   uint8
	GbeID     uint16
	GbeRead   uint8
	GbeWrite  uint8
}

func (m FlashMasterSection) String() string {
	return fmt.Sprintf("FlashMasterSection{BiosID=%v, MeID=%v, GbeID=%v}",
		m.BiosID, m.MeID, m.GbeID)
}

// Summary prints a multi-line description of the FlashMasterSection
func (m FlashMasterSection) Summary() string {
	return fmt.Sprintf("FlashMasterSection{\n"+
		"    BiosID=%v\n"+
		"    BiosRead=%v\n"+
		"    BiosWrite=%v\n"+
		"    MeID=%v\n"+
		"    MeRead=%v\n"+
		"    MeWrite=%v\n"+
		"    GbeID=%v\n"+
		"    GbeRead=%v\n"+
		"    GbeWrite=%v\n"+
		"}",
		m.BiosID, m.BiosRead, m.BiosWrite,
		m.MeID, m.MeRead, m.MeWrite,
		m.GbeID, m.GbeRead, m.GbeWrite,
	)
}

// NewFlashMasterSection parses a sequence of bytes and returns a FlashMasterSection
// object, if a valid one is passed, or an error
func NewFlashMasterSection(buf []byte) (*FlashMasterSection, error) {
	if len(buf) < FlashMasterSectionSize {
		return nil, fmt.Errorf("Flash Master Section size too small: expected %v bytes, got %v",
			FlashMasterSectionSize,
			len(buf),
		)
	}
	var master FlashMasterSection
	reader := bytes.NewReader(buf)
	if err := binary.Read(reader, binary.LittleEndian, &master); err != nil {
		return nil, err
	}
	return &master, nil
}
