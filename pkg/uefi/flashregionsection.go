// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// FlashRegionSectionSize is the size of the Region descriptor. It is made up by 16 fields, each 2x16-bits large.
const FlashRegionSectionSize = 64

// FlashRegionSection holds the metadata of all the different flash regions like PDR, Gbe and the Bios region.
type FlashRegionSection struct {
	_                   uint16
	FlashBlockEraseSize uint16

	// This isn't documented anywhere, but I've only seen images with 16 slots for FlashRegion entries, with the
	// FlashMasterSection coming immediately after, so I'm assuming that's the max for now.
	FlashRegions [15]FlashRegion
}

// ValidRegions returns a list of names of the regions with non-zero size.
func (f *FlashRegionSection) ValidRegions() []string {
	var regions []string
	for i, r := range f.FlashRegions {
		if r.Valid() {
			regions = append(regions, flashRegionTypeNames[FlashRegionType(i)])
		}
	}
	return regions
}

func (f *FlashRegionSection) String() string {
	return fmt.Sprintf("FlashRegionSection{Regions=%v}",
		strings.Join(f.ValidRegions(), ","),
	)
}

// NewFlashRegionSection initializes a FlashRegionSection from a slice of bytes
func NewFlashRegionSection(data []byte) (*FlashRegionSection, error) {
	if len(data) < FlashRegionSectionSize {
		return nil, fmt.Errorf("flash Region Section size too small: expected %v bytes, got %v",
			FlashRegionSectionSize,
			len(data),
		)
	}
	var region FlashRegionSection
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &region); err != nil {
		return nil, err
	}
	return &region, nil
}
