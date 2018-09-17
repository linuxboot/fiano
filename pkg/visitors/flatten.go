// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// Flatten places all nodes into a single slice and removes their children.
// Each node contains the index of its parent (the root node's parent is
// itself). This format is suitable for insertion into a database.
type Flatten struct {
	// Optionally write result as JSON.
	W io.Writer

	// Outputted flattened tree.
	List []FlattenedFirmware

	parent int
}

// FlattenedFirmware appears in the Flatten.List, contains the index of the
// parrent and has no children.
type FlattenedFirmware struct {
	Parent int
	Type   string
	Value  uefi.Firmware
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Flatten) Run(f uefi.Firmware) error {
	if err := f.Apply(v); err != nil {
		return err
	}

	// Remove children otherwise the output contains many duplicates of each node.
	for _, f := range v.List {
		switch f := f.Value.(type) {
		case *uefi.BIOSRegion:
			f.Elements = nil
		case *uefi.File:
			f.Sections = nil
		case *uefi.FirmwareVolume:
			f.Files = nil
		case *uefi.FlashImage:
			// TODO: Cannot remove IFD
			// f.IFD = nil
			f.BIOS = nil
			f.ME = nil
			f.GBE = nil
			f.PD = nil
		case *uefi.Section:
			f.Encapsulated = nil
		}
	}

	// Optionally print as JSON
	if v.W != nil {
		b, err := json.MarshalIndent(v.List, "", "\t")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(v.W, string(b))
		return err
	}
	return nil
}

// Visit applies the Flatten visitor to any Firmware type.
func (v *Flatten) Visit(f uefi.Firmware) error {
	parent := v.parent
	v.parent = len(v.List)
	v.List = append(v.List, FlattenedFirmware{
		Parent: parent,
		Type:   fmt.Sprintf("%T", f),
		Value:  f,
	})
	if err := f.ApplyChildren(v); err != nil {
		return err
	}
	v.parent = parent
	return nil
}

func init() {
	RegisterCLI("flatten", "prints a JSON list of nodes", 0, func(args []string) (uefi.Visitor, error) {
		return &Flatten{
			W: os.Stdout,
		}, nil
	})
}
