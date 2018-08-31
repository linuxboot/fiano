// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/linuxboot/fiano/pkg/uefi"
)

var (
	force  = flag.Bool("force", false, "force extract to non empty directory")
	remove = flag.Bool("remove", false, "remove existing directory before extracting")
)

// Extract extracts any Firmware node to DirPath
type Extract struct {
	DirPath string
	Index   *uint64
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Extract) Run(f uefi.Firmware) error {
	// Optionally remove directory if it already exists.
	if *remove {
		if err := os.RemoveAll(v.DirPath); err != nil {
			return err
		}
	}

	if !*force {
		// Check that directory does not exist or is empty.
		files, err := ioutil.ReadDir(v.DirPath)
		if err == nil {
			if len(files) != 0 {
				return errors.New("Existing directory not empty, use --force to override")
			}
		} else if !os.IsNotExist(err) {
			// Error was not EEXIST, we do not know what went wrong.
			return err
		}
	}

	// Create the directory if it does not exist.
	if err := os.MkdirAll(v.DirPath, 0755); err != nil {
		return err
	}

	// Change working directory so we can use relative paths.
	// TODO: commands after this in the pipeline are in unexpected directory
	if err := os.Chdir(v.DirPath); err != nil {
		return err
	}

	var fileIndex uint64
	if err := f.Apply(&Extract{DirPath: ".", Index: &fileIndex}); err != nil {
		return err
	}

	// Output summary json.
	json, err := uefi.MarshalFirmware(f)
	if err != nil {
		return err
	}
	return ioutil.WriteFile("summary.json", json, 0666)
}

// Visit applies the Extract visitor to any Firmware type.
func (v *Extract) Visit(f uefi.Firmware) error {
	// The visitor must be cloned before modification; otherwise, the
	// sibling's values are modified.
	v2 := *v

	var err error
	switch f := f.(type) {

	case *uefi.FirmwareVolume:
		v2.DirPath = filepath.Join(v.DirPath, fmt.Sprintf("%#x", f.FVOffset))
		if len(f.Files) == 0 {
			f.ExtractPath, err = uefi.ExtractBinary(f.Buf(), v2.DirPath, "fv.bin")
		} else {
			f.ExtractPath, err = uefi.ExtractBinary(f.Buf()[:f.DataOffset], v2.DirPath, "fvh.bin")
		}

	case *uefi.File:
		// For files we use the GUID as the folder name.
		v2.DirPath = filepath.Join(v.DirPath, f.Header.UUID.String())
		// Crappy hack to make unique ids unique
		v2.DirPath = filepath.Join(v2.DirPath, fmt.Sprint(*v.Index))
		*v.Index++
		if len(f.Sections) == 0 {
			f.ExtractPath, err = uefi.ExtractBinary(f.Buf(), v2.DirPath, fmt.Sprintf("%v.ffs", f.Header.UUID))
		}

	case *uefi.Section:
		// For sections we use the file order as the folder name.
		v2.DirPath = filepath.Join(v.DirPath, fmt.Sprint(f.FileOrder))
		if len(f.Encapsulated) == 0 {
			f.ExtractPath, err = uefi.ExtractBinary(f.Buf(), v2.DirPath, fmt.Sprintf("%v.sec", f.FileOrder))
		}

	case *uefi.FlashDescriptor:
		v2.DirPath = filepath.Join(v.DirPath, "ifd")
		f.ExtractPath, err = uefi.ExtractBinary(f.Buf(), v2.DirPath, "flashdescriptor.bin")

	case *uefi.BIOSRegion:
		v2.DirPath = filepath.Join(v.DirPath, "bios")
		if len(f.Elements) == 0 {
			f.ExtractPath, err = uefi.ExtractBinary(f.Buf(), v2.DirPath, "biosregion.bin")
		}

	case *uefi.GBERegion:
		v2.DirPath = filepath.Join(v.DirPath, "gbe")
		f.ExtractPath, err = uefi.ExtractBinary(f.Buf(), v2.DirPath, "gberegion.bin")

	case *uefi.MERegion:
		v2.DirPath = filepath.Join(v.DirPath, "me")
		f.ExtractPath, err = uefi.ExtractBinary(f.Buf(), v2.DirPath, "meregion.bin")

	case *uefi.PDRegion:
		v2.DirPath = filepath.Join(v.DirPath, "pd")
		f.ExtractPath, err = uefi.ExtractBinary(f.Buf(), v2.DirPath, "pdregion.bin")

	case *uefi.BIOSPadding:
		v2.DirPath = filepath.Join(v.DirPath, fmt.Sprintf("biospad_%#x", f.Offset))
		f.ExtractPath, err = uefi.ExtractBinary(f.Buf(), v2.DirPath, "pad.bin")
	}
	if err != nil {
		return err
	}

	return f.ApplyChildren(&v2)
}

func init() {
	var fileIndex uint64
	RegisterCLI("extract", 1, func(args []string) (uefi.Visitor, error) {
		return &Extract{
			DirPath: args[0],
			Index:   &fileIndex,
		}, nil
	})
}
