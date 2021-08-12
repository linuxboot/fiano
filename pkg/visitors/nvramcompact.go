// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/uefi"
)

func compactNVarStore(s *uefi.NVarStore) error {
	var keepEntries []*uefi.NVar
	linkedNVar := make(map[uint64]*uefi.NVar)
	// Find Data entries and associated metadata entries
	for _, v := range s.Entries {
		if !v.IsValid() {
			continue
		}
		h, ok := linkedNVar[v.Offset]
		if !ok {
			h = v
		}
		if v.NextOffset != 0 {
			linkedNVar[v.NextOffset] = h
			continue
		}
		linkedNVar[v.Offset] = h
		keepEntries = append(keepEntries, v)
	}
	var newEntries []*uefi.NVar
	var guidStore []guid.GUID
	guidStoredIndex := make(map[guid.GUID]uint8)
	var offset uint64
	// Rebuild GUID store and entries
	for _, k := range keepEntries {
		h := linkedNVar[k.Offset]
		v := uefi.NVar{Type: uefi.FullNVarEntry, Header: h.Header, GUID: h.GUID, Name: h.Name, Offset: offset, NVarStore: k.NVarStore}
		if v.Header.Attributes&uefi.NVarEntryGUID == 0 {
			guidIndex, ok := guidStoredIndex[v.GUID]
			if !ok {

				guidIndex = uint8(len(guidStore))
				guidStoredIndex[v.GUID] = guidIndex
				guidStore = append(guidStore, v.GUID)
			}
			v.GUIDIndex = &guidIndex

		}
		if err := v.Assemble(k.Buf()[k.DataOffset:], false); err != nil {
			return err
		}
		offset += uint64(len(v.Buf()))
		newEntries = append(newEntries, &v)
	}
	// replace entries and GUID store
	s.Entries = newEntries
	s.GUIDStore = guidStore

	// Assemble the tree just to make sure things are right
	// It will do the mandatory second Assemble of NVar and update the Offsets
	a := &Assemble{}
	return a.Run(s)
}

// NVRamCompact compact nvram content by removing old version of variables
type NVRamCompact struct {
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *NVRamCompact) Run(f uefi.Firmware) error {
	return f.Apply(v)
}

// Visit applies the NVRamCompact visitor to any Firmware type.
func (v *NVRamCompact) Visit(f uefi.Firmware) error {
	switch f := f.(type) {
	case *uefi.NVarStore:
		// First apply to children to compact nested stores in vars
		err := f.ApplyChildren(v)
		if err != nil {
			return err
		}
		// call the compact function
		return compactNVarStore(f)
	}
	return f.ApplyChildren(v)
}

func init() {
	RegisterCLI("nvram-compact", "compact nvram content by removing old versions of variables", 0, func(args []string) (uefi.Visitor, error) {
		return &NVRamCompact{}, nil
	})
}
