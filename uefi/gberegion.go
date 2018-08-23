// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

import (
	"errors"
	"fmt"
	"io/ioutil"
)

// GBERegion represents the GBE Region in the firmware.
type GBERegion struct {
	// holds the raw data
	Buf []byte `json:"-"`
	//Metadata for extraction and recovery
	ExtractPath string
	// This is a pointer to the Region struct laid out in the ifd
	Position *Region
}

// NewGBERegion parses a sequence of bytes and returns a GBERegion
// object, if a valid one is passed, or an error. It also points to the
// Region struct uncovered in the ifd.
func NewGBERegion(buf []byte, r *Region) (*GBERegion, error) {
	gbe := GBERegion{Buf: buf, Position: r}
	return &gbe, nil
}

// Apply calls the visitor on the GBERegion.
func (gbe *GBERegion) Apply(v Visitor) error {
	return v.Visit(gbe)
}

// ApplyChildren calls the visitor on each child node of GBERegion.
func (gbe *GBERegion) ApplyChildren(v Visitor) error {
	return nil
}

// Validate Region
func (gbe *GBERegion) Validate() []error {
	// TODO: Add more verification if needed.
	errs := make([]error, 0)
	if gbe.Position == nil {
		errs = append(errs, errors.New("GBERegion position is nil"))
	}
	if !gbe.Position.Valid() {
		errs = append(errs, fmt.Errorf("GBERegion is not valid, region was %v", *gbe.Position))
	}
	return errs
}

// Assemble assembles the GBE Region from the binary file.
func (gbe *GBERegion) Assemble() ([]byte, error) {
	var err error
	gbe.Buf, err = ioutil.ReadFile(gbe.ExtractPath)
	if err != nil {
		return nil, err
	}
	return gbe.Buf, nil
}
