package psb

import (
	"fmt"
	"io"

	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
)

// extractRawEntry extracts a generic entry raw entry from either PSP Directory Table or BIOS Directory Table
func extractRawEntry(amdFw *amd_manifest.AMDFirmware, level uint, directoryType string, id uint64) ([]byte, error) {

	switch directoryType {
	case "bios":
		biosDirectory, err := getBIOSTable(amdFw, level)
		if err != nil {
			return nil, fmt.Errorf("cannot extract BIOS Directory of level %d", level)
		}
		for _, entry := range biosDirectory.Entries {
			if entry.Type == amd_manifest.BIOSDirectoryTableEntryType(id) {
				firmwareBytes := amdFw.Firmware().ImageBytes()
				start := entry.SourceAddress
				end := start + uint64(entry.Size)
				if err := checkBoundaries(start, end, firmwareBytes); err != nil {
					return nil, fmt.Errorf("cannot extract BIOS entry %x level %d from firmware image, boundary check fail: %w", id, level, err)
				}
				return firmwareBytes[start:end], nil
			}
		}
		return nil, fmt.Errorf("could not find entry %x in BIOS Directory level %d", id, level)
	case "psp":
		pspDirectory, err := getPSPTable(amdFw, level)
		if err != nil {
			return nil, fmt.Errorf("cannot extract PSP Directory of level %d", level)
		}
		for _, entry := range pspDirectory.Entries {
			if entry.Type == amd_manifest.PSPDirectoryTableEntryType(id) {
				firmwareBytes := amdFw.Firmware().ImageBytes()
				start := entry.LocationOrValue
				end := start + uint64(entry.Size)
				if err := checkBoundaries(start, end, firmwareBytes); err != nil {
					return nil, fmt.Errorf("cannot extract PSP entry %x level %d from firmware image, boundary check fail: %w", id, level, err)
				}
				return firmwareBytes[start:end], nil
			}
		}
		return nil, fmt.Errorf("could not find entry %x in PSP Directory level %d", id, level)
	}

	return nil, fmt.Errorf("do not recognize directory type '%s'", directoryType)
}

// DumpEntry dumps an entry from either PSP Directory or BIOS directory to a file on the filesystem
func DumpEntry(amdFw *amd_manifest.AMDFirmware, level uint, directoryType string, id uint64, w io.Writer) (int, error) {

	var data []byte

	data, err := extractRawEntry(amdFw, level, directoryType, id)
	if err != nil {
		return 0, fmt.Errorf("could not extract entry 0x%x from BIOS table: %w", id, err)
	}

	return w.Write(data)
}

// PatchEntry takes an AmdFirmware object and modifies one entry in either the PSP or BIOS directory tables.
// The modified entry is read from `r` reader object, while the modified firmware is written into `w` writer object.
func PatchEntry(amdFw *amd_manifest.AMDFirmware, level uint, directoryType string, id uint64, r io.Reader, w io.Writer) (int, error) {

	var start, end uint64

	switch directoryType {
	case "bios":
		biosDirectory, err := getBIOSTable(amdFw, level)
		if err != nil {
			return 0, fmt.Errorf("cannot extract BIOS Directory of level %d", level)
		}
		for _, entry := range biosDirectory.Entries {
			if entry.Type == amd_manifest.BIOSDirectoryTableEntryType(id) {
				start = entry.SourceAddress
				end = start + uint64(entry.Size)
			}
		}
	case "psp":
		pspDirectory, err := getPSPTable(amdFw, level)
		if err != nil {
			return 0, fmt.Errorf("cannot extract PSP Directory of level %d", level)
		}
		for _, entry := range pspDirectory.Entries {
			if entry.Type == amd_manifest.PSPDirectoryTableEntryType(id) {
				start = entry.LocationOrValue
				end = start + uint64(entry.Size)
			}
		}
	default:
		return 0, fmt.Errorf("do not recognize directory type '%s'", directoryType)
	}

	if end == 0 || end-start == 0 || start > end {
		return 0, fmt.Errorf("entry level %d, type %s, start, end, size = (%d, %d), size cannot be zero or negative", level, directoryType, start, end)
	}

	modifiedEntry, err := io.ReadAll(r)
	if err != nil {
		return 0, fmt.Errorf("could not read modified entry: %w", err)
	}

	firmwareBytes := amdFw.Firmware().ImageBytes()

	if err := checkBoundaries(start, end, firmwareBytes); err != nil {
		return 0, fmt.Errorf("cannot extract key database from firmware image, boundary check fail: %w", err)
	}

	size := end - start
	if uint64(end-start) != uint64(len(modifiedEntry)) {
		return 0, fmt.Errorf("cannot write the entry to the firmware image, entry size check fail, expected %d, modified entry is %d", uint64(size), uint64(len(modifiedEntry)))
	}

	firmwareBytesFirstSection := firmwareBytes[0:start]
	firmwareBytesSecondSection := firmwareBytes[end:]

	// Write the firmware to the writer object. firmwareBytes is not modified in place because it would segfault.
	// The reason is the following:
	// * We read the firmware with uefi.ParseUEFIFirmwareFile in https://github.com/9elements/converged-security-suite/blob/master/pkg/uefi/uefi.go#L43
	// * That by default maps as read only:
	//   https://github.com/9elements/converged-security-suite/blob/81375eac5ccc858045c91323eac8e60233dc9882/pkg/ostools/file_to_bytes.go#L25
	// * Later, the behavior can be modified with ReadOnly flag in
	//   https://github.com/linuxboot/fiano/blob/master/pkg/uefi/uefi.go#L24, which is in turn consumed from NewBIOSRegion.
	// * If ReadOnly is not set, the whole slice is copied into memory from the mapped region:
	//   https://github.com/linuxboot/fiano/blob/43cb7391010ac6cb416ab6f641a3a5465b5f524e/pkg/uefi/biosregion.go#L88
	//
	// Converged security suite sets read-only to true: https://github.com/9elements/converged-security-suite/blob/master/pkg/uefi/uefi.go#L30
	// Therefore, firmwareBytes is read-only memmapped region. In order to make it read-write, we would need to enable the copy approach
	// and set ReadOnly to false (fianoUEFI.ReadOnly = false)
	// We take a more explicit approach and write the memory area before the corrupted region, the corrupted region itself,
	// and the memory area after the corrupted region.
	n, err := w.Write(firmwareBytesFirstSection)
	if err != nil {
		return n, fmt.Errorf("could not write entry to system file :  %w", err)
	}
	m, err := w.Write(modifiedEntry)
	if err != nil {
		return n, fmt.Errorf("could not write entry to system file :  %w", err)
	}
	j, err := w.Write(firmwareBytesSecondSection)
	if err != nil {
		return n, fmt.Errorf("could not write entry to system file :  %w", err)
	}

	n = n + m + j
	return n, nil
}
