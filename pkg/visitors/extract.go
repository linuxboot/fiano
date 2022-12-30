// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"errors"
	"flag"
	"fmt"
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
	BasePath string
	DirPath  string
	Index    *uint64
}

// extractBinary simply dumps the binary to a specified directory and filename.
// It creates the directory if it doesn't already exist, and dumps the buffer to it.
// It returns the filepath of the binary, and an error if it exists.
// This is meant as a helper function for other Extract functions.
func (v *Extract) extractBinary(buf []byte, filename string) (string, error) {
	// Create the directory if it doesn't exist
	dirPath := filepath.Join(v.BasePath, v.DirPath)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return "", err
	}

	// Dump the binary.
	fp := filepath.Join(dirPath, filename)
	if err := os.WriteFile(fp, buf, 0666); err != nil {
		// Make sure we return "" since we don't want an invalid path to be serialized out.
		return "", err
	}
	// Return only the relative path from the root of the tree
	return filepath.Join(v.DirPath, filename), nil
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Extract) Run(f uefi.Firmware) error {
	// Optionally remove directory if it already exists.
	if *remove {
		if err := os.RemoveAll(v.BasePath); err != nil {
			return err
		}
	}

	if !*force {
		// Check that directory does not exist or is empty.
		files, err := os.ReadDir(v.BasePath)
		if err == nil {
			if len(files) != 0 {
				return errors.New("existing directory not empty, use --force to override")
			}
		} else if !os.IsNotExist(err) {
			// Error was not EEXIST, we do not know what went wrong.
			return err
		}
	}

	// Create the directory if it does not exist.
	if err := os.MkdirAll(v.BasePath, 0755); err != nil {
		return err
	}

	// Reset the index
	*v.Index = 0
	if err := f.Apply(v); err != nil {
		return err
	}

	// Output summary json.
	json, err := uefi.MarshalFirmware(f)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(v.BasePath, "summary.json"), json, 0666)
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
			f.ExtractPath, err = v2.extractBinary(f.Buf(), "fv.bin")
		} else {
			f.ExtractPath, err = v2.extractBinary(f.Buf()[:f.DataOffset], "fvh.bin")
		}

	case *uefi.File:
		// For files we use the GUID as the folder name.
		v2.DirPath = filepath.Join(v.DirPath, f.Header.GUID.String())
		// Crappy hack to make unique ids unique
		v2.DirPath = filepath.Join(v2.DirPath, fmt.Sprint(*v.Index))
		*v.Index++
		if len(f.Sections) == 0 && f.NVarStore == nil {
			f.ExtractPath, err = v2.extractBinary(f.Buf(), fmt.Sprintf("%v.ffs", f.Header.GUID))
		}

	case *uefi.Section:
		// For sections we use the file order as the folder name.
		v2.DirPath = filepath.Join(v.DirPath, fmt.Sprint(f.FileOrder))
		if len(f.Encapsulated) == 0 {
			f.ExtractPath, err = v2.extractBinary(f.Buf(), fmt.Sprintf("%v.sec", f.FileOrder))
		}

	case *uefi.NVar:
		// For NVar we use the GUID as the folder name the Name as file name and add the offset to links to make them unique
		v2.DirPath = filepath.Join(v.DirPath, f.GUID.String())
		if f.IsValid() {
			if f.NVarStore == nil {
				if f.Type == uefi.LinkNVarEntry {
					f.ExtractPath, err = v2.extractBinary(f.Buf()[f.DataOffset:], fmt.Sprintf("%v-%#x.bin", f.Name, f.Offset))
				} else {
					f.ExtractPath, err = v2.extractBinary(f.Buf()[f.DataOffset:], fmt.Sprintf("%v.bin", f.Name))
				}
			}
		} else {
			f.ExtractPath, err = v2.extractBinary(f.Buf(), fmt.Sprintf("%#x.nvar", f.Offset))
		}

	case *uefi.FlashDescriptor:
		v2.DirPath = filepath.Join(v.DirPath, "ifd")
		f.ExtractPath, err = v2.extractBinary(f.Buf(), "flashdescriptor.bin")

	case *uefi.BIOSRegion:
		v2.DirPath = filepath.Join(v.DirPath, "bios")
		if len(f.Elements) == 0 {
			f.ExtractPath, err = v2.extractBinary(f.Buf(), "biosregion.bin")
		}

	case *uefi.MERegion:
		v2.DirPath = filepath.Join(v.DirPath, "me")
		f.ExtractPath, err = v2.extractBinary(f.Buf(), "meregion.bin")

	case *uefi.RawRegion:
		v2.DirPath = filepath.Join(v.DirPath, f.Type().String())
		f.ExtractPath, err = v2.extractBinary(f.Buf(), fmt.Sprintf("%#x.bin", f.FlashRegion().BaseOffset()))

	case *uefi.BIOSPadding:
		v2.DirPath = filepath.Join(v.DirPath, fmt.Sprintf("biospad_%#x", f.Offset))
		f.ExtractPath, err = v2.extractBinary(f.Buf(), "pad.bin")
	}
	if err != nil {
		return err
	}

	return f.ApplyChildren(&v2)
}

func init() {
	var fileIndex uint64
	RegisterCLI("extract", "extract dir\n extract the files to directory `dir`", 1, func(args []string) (uefi.Visitor, error) {
		return &Extract{
			BasePath: args[0],
			DirPath:  ".",
			Index:    &fileIndex,
		}, nil
	})
}
