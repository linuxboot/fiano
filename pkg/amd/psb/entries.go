package psb

import (
	"fmt"
	"os"

	amd_manifest "github.com/9elements/converged-security-suite/pkg/amd/manifest"
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
func DumpEntry(amdFw *amd_manifest.AMDFirmware, level uint, directoryType string, id uint64, entryFile string) (int, error) {

	var data []byte

	data, err := extractRawEntry(amdFw, level, directoryType, id)
	if err != nil {
		return 0, fmt.Errorf("could not extract entry 0x%x from BIOS table: %w", id, err)
	}

	fs, err := os.Create(entryFile)
	if err != nil {
		return 0, fmt.Errorf("could not create new system file :  %w", err)
	}

	defer fs.Close()

	n, err := fs.Write(data)
	if err != nil {
		return n, fmt.Errorf("could not write entry to system file :  %w", err)
	}
	return n, nil
}

// PatchEntry takes a path on the filesystem pointing to a dump of either a PSP entry or a BIOS entry and re-apply it to the firmware
func PatchEntry(amdFw *amd_manifest.AMDFirmware, level uint, directoryType string, id uint64, entryFile string, modifiedFirmwareFile string) (int, error) {

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

	modifiedEntry, err := os.ReadFile(entryFile)
	if err != nil {
		return 0, fmt.Errorf("could not read Modified entry: %w", err)
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

	//write the firmware to a different file
	fs, err := os.Create(modifiedFirmwareFile)
	if err != nil {
		return 0, fmt.Errorf("could not create new system file :  %w", err)
	}

	defer fs.Close()

	n, err := fs.Write(firmwareBytesFirstSection)
	if err != nil {
		return n, fmt.Errorf("could not write entry to system file :  %w", err)
	}
	m, err := fs.Write(modifiedEntry)
	if err != nil {
		return n, fmt.Errorf("could not write entry to system file :  %w", err)
	}
	j, err := fs.Write(firmwareBytesSecondSection)
	if err != nil {
		return n, fmt.Errorf("could not write entry to system file :  %w", err)
	}

	n = n + m + j
	return n, nil
}
