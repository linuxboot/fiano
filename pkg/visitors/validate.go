// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// Validate performs extra checks on the firmware image.
type Validate struct {
	// An optional Writer for writing errors when validation is complete.
	// When the writer it set, Run will also call os.Exit(1) upon finding
	// an error.
	W io.Writer

	// List of validation errors.
	Errors []error
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Validate) Run(f uefi.Firmware) error {
	if err := f.Apply(v); err != nil {
		return err
	}

	if v.W != nil && len(v.Errors) != 0 {
		for _, e := range v.Errors {
			fmt.Println(e)
		}
		os.Exit(1)
	}
	return nil
}

// Visit applies the Validate visitor to any Firmware type.
func (v *Validate) Visit(f uefi.Firmware) error {
	// TODO: add more verification where needed
	switch f := f.(type) {
	case *uefi.FlashImage:
		_, err := f.FindSignature()
		if err != nil {
			v.Errors = append(v.Errors, err)
		}

	case *uefi.FlashDescriptor:
		d := f.DescriptorMap
		if d.MasterBase > uefi.FlashDescriptorMapMaxBase {
			v.Errors = append(v.Errors, fmt.Errorf("MasterBase too large: expected %v bytes, got %v",
				uefi.FlashDescriptorMapMaxBase,
				d.MasterBase,
			))
		}
		if d.RegionBase > uefi.FlashDescriptorMapMaxBase {
			v.Errors = append(v.Errors, fmt.Errorf("RegionBase too large: expected %v bytes, got %v",
				uefi.FlashDescriptorMapMaxBase,
				d.RegionBase,
			))
		}
		if d.MasterBase > uefi.FlashDescriptorMapMaxBase {
			v.Errors = append(v.Errors, fmt.Errorf("ComponentBase too large: expected %v bytes, got %v",
				uefi.FlashDescriptorMapMaxBase,
				d.MasterBase,
			))
		}
		if d.MasterBase == d.RegionBase {
			v.Errors = append(v.Errors, fmt.Errorf("MasterBase must be different from RegionBase: both are at 0x%x",
				d.MasterBase,
			))
		}
		if d.MasterBase == d.ComponentBase {
			v.Errors = append(v.Errors, fmt.Errorf("MasterBase must be different from ComponentBase: both are at 0x%x",
				d.MasterBase,
			))
		}
		if d.RegionBase == d.ComponentBase {
			v.Errors = append(v.Errors, fmt.Errorf("RegionBase must be different from ComponentBase: both are at 0x%x",
				d.RegionBase,
			))
		}

	case *uefi.FirmwareVolume:
		// Check for min length
		fvlen := uint64(len(f.Buf()))
		// We need this check in case HeaderLen doesn't exist, and bail out early
		if fvlen < uefi.FirmwareVolumeMinSize {
			v.Errors = append(v.Errors, fmt.Errorf("length too small!, buffer is only %#x bytes long", fvlen))
			break
		}
		// Check header length
		if f.HeaderLen < uefi.FirmwareVolumeMinSize {
			v.Errors = append(v.Errors, fmt.Errorf("header length too small, got: %#x", f.HeaderLen))
			break
		}
		// Check for full header and bail out if its not fully formed.
		if fvlen < uint64(f.HeaderLen) {
			v.Errors = append(v.Errors, fmt.Errorf("buffer smaller than header!, header is %#x bytes, buffer is %#x bytes",
				f.HeaderLen, fvlen))
			break
		}
		// Do we want to fail in this case? maybe not.
		if uefi.FVGUIDs[f.FileSystemGUID] == "" {
			v.Errors = append(v.Errors, fmt.Errorf("unknown FV type! Guid was %v", f.FileSystemGUID))
		}
		// UEFI PI spec says version should always be 2
		if f.Revision != 2 {
			v.Errors = append(v.Errors, fmt.Errorf("revision should be 2, was %v", f.Revision))
		}
		// Check Signature
		fvSigInt := binary.LittleEndian.Uint32([]byte("_FVH"))
		if f.Signature != fvSigInt {
			v.Errors = append(v.Errors, fmt.Errorf("signature was not _FVH, got: %#08x", f.Signature))
		}
		// Check length
		if f.Length != fvlen {
			v.Errors = append(v.Errors, fmt.Errorf("length mismatch!, header has %#x, buffer is %#x bytes long", f.Length, fvlen))
		}
		// Check checksum
		sum, err := uefi.Checksum16(f.Buf()[:f.HeaderLen]) // TODO: use the Header() function which does not exist yet
		if err != nil {
			v.Errors = append(v.Errors, fmt.Errorf("unable to checksum FV header: %v", err))
		} else if sum != 0 {
			v.Errors = append(v.Errors, fmt.Errorf("header did not sum to 0, got: %#x", sum))
		}

	case *uefi.File:
		buflen := uint64(len(f.Buf()))
		blankSize := [3]uint8{0xFF, 0xFF, 0xFF}
		if buflen < uefi.FileHeaderMinLength {
			v.Errors = append(v.Errors, fmt.Errorf("file length too small!, buffer is only %#x bytes long", buflen))
			break
		}

		// Size Checks
		fh := &f.Header
		if fh.Size == blankSize {
			if buflen < uefi.FileHeaderExtMinLength {
				v.Errors = append(v.Errors, fmt.Errorf("file %v length too small!, buffer is only %#x bytes long for extended header",
					fh.GUID, buflen))
				break
			}
			if !fh.Attributes.IsLarge() {
				v.Errors = append(v.Errors, fmt.Errorf("file %v using extended header, but large attribute is not set",
					fh.GUID))
				break
			}
		} else if uefi.Read3Size(f.Header.Size) != fh.ExtendedSize {
			v.Errors = append(v.Errors, fmt.Errorf("file %v size not copied into extendedsize",
				fh.GUID))
			break
		}
		if buflen != fh.ExtendedSize {
			v.Errors = append(v.Errors, fmt.Errorf("file %v size mismatch! Size is %#x, buf length is %#x",
				fh.GUID, fh.ExtendedSize, buflen))
			break
		}

		// Header Checksums
		if sum := f.ChecksumHeader(); sum != 0 {
			v.Errors = append(v.Errors, fmt.Errorf("file %v header checksum failure! sum was %v",
				fh.GUID, sum))
		}

		// Body Checksum
		if !fh.Attributes.HasChecksum() && fh.Checksum.File != uefi.EmptyBodyChecksum {
			v.Errors = append(v.Errors, fmt.Errorf("file %v body checksum failure! Attribute was not set, but sum was %v instead of %v",
				fh.GUID, fh.Checksum.File, uefi.EmptyBodyChecksum))
		} else if fh.Attributes.HasChecksum() {
			headerSize := uefi.FileHeaderMinLength
			if fh.Attributes.IsLarge() {
				headerSize = uefi.FileHeaderExtMinLength
			}
			if sum := uefi.Checksum8(f.Buf()[headerSize:]); sum != 0 { // TODO: use the Payload function which does not exist yet
				v.Errors = append(v.Errors, fmt.Errorf("file %v body checksum failure! sum was %v",
					fh.GUID, sum))
			}
		}

	case *uefi.Section:
		buflen := uint32(len(f.Buf()))
		blankSize := [3]uint8{0xFF, 0xFF, 0xFF}

		// Size Checks
		sh := &f.Header
		if sh.Size == blankSize {
			if buflen < uefi.SectionExtMinLength {
				v.Errors = append(v.Errors, fmt.Errorf("section length too small!, buffer is only %#x bytes long for extended header",
					buflen))
				break
			}
		} else if uint32(uefi.Read3Size(f.Header.Size)) != sh.ExtendedSize {
			v.Errors = append(v.Errors, errors.New("section size not copied into extendedsize"))
			break
		}
		if buflen != sh.ExtendedSize {
			v.Errors = append(v.Errors, fmt.Errorf("section size mismatch! Size is %#x, buf length is %#x",
				sh.ExtendedSize, buflen))
			break
		}

	case *uefi.BIOSRegion:
		if f.FlashRegion() != nil && !f.FlashRegion().Valid() {
			v.Errors = append(v.Errors, fmt.Errorf("BIOSRegion is not valid, region was %v", *f.FlashRegion()))
		}

		if _, err := f.FirstFV(); err != nil {
			v.Errors = append(v.Errors, err)
		}

		for i, e := range f.Elements {
			if err := e.Value.Apply(v); err != nil {
				return err
			}
			f, ok := e.Value.(*uefi.FirmwareVolume)
			if !ok {
				// Not a firmware volume
				continue
			}
			// We have to do this because they didn't put an encapsulating structure around the FVs.
			// This means it's possible for different firmware volumes to report different erase polarities.
			// Now we have to check to see if we're in some insane state.
			if ep := f.GetErasePolarity(); ep != uefi.Attributes.ErasePolarity {
				v.Errors = append(v.Errors, fmt.Errorf("erase polarity mismatch! fv 0 has %#x and fv %d has %#x",
					uefi.Attributes.ErasePolarity, i, ep))
			}
		}
		return nil // We already traversed the children manually.

	case *uefi.RawRegion:
		if f.FlashRegion() == nil {
			v.Errors = append(v.Errors, errors.New("Region position is nil"))
		}
		if !f.FlashRegion().Valid() {
			v.Errors = append(v.Errors, fmt.Errorf("Region is not valid, region was %v", *f.FlashRegion()))
		}
	}
	return f.ApplyChildren(v)
}

func init() {
	RegisterCLI("validate", "perform extra validation checks", 0, func(args []string) (uefi.Visitor, error) {
		return &Validate{}, nil
	})
}
