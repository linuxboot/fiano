package psb

import (
	"fmt"
	"io"
	"sort"
	"strings"

	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
	bytes2 "github.com/linuxboot/fiano/pkg/bytes"
)

// DirectoryType denotes specific firmware table in PSP firmware
type DirectoryType uint8

const (
	// PSPDirectoryLevel1 represents PSP directory table level 1
	PSPDirectoryLevel1 DirectoryType = iota
	// PSPDirectoryLevel2 represents PSP directory table level 2
	PSPDirectoryLevel2
	// BIOSDirectoryLevel1 represents BIOS directory table level 1
	BIOSDirectoryLevel1
	// BIOSDirectoryLevel2 represents BIOS directory table level 2
	BIOSDirectoryLevel2
)

var allDirectoryTypes = []DirectoryType{
	PSPDirectoryLevel1,
	PSPDirectoryLevel2,
	BIOSDirectoryLevel1,
	BIOSDirectoryLevel2,
}

// AllDirectoryTypes returns all directory types
func AllDirectoryTypes() []DirectoryType {
	result := make([]DirectoryType, len(allDirectoryTypes))
	copy(result, allDirectoryTypes)
	return result
}

// ShortName returns a short name of directory type
func (t DirectoryType) ShortName() string {
	switch t {
	case PSPDirectoryLevel1:
		return "PSPDirectoryLevel1"
	case PSPDirectoryLevel2:
		return "PSPDirectoryLevel2"
	case BIOSDirectoryLevel1:
		return "BIOSDirectoryLevel1"
	case BIOSDirectoryLevel2:
		return "BIOSDirectoryLevel2"
	}
	return fmt.Sprintf("Unknown firmware directory type: '%d'", t)
}

func (t DirectoryType) String() string {
	switch t {
	case PSPDirectoryLevel1:
		return "PSP directory level 1"
	case PSPDirectoryLevel2:
		return "PSP directory level 2"
	case BIOSDirectoryLevel1:
		return "BIOS directory level 1"
	case BIOSDirectoryLevel2:
		return "BIOS directory level 2"
	}
	return fmt.Sprintf("Unknown PSP firmware directory type: '%d'", t)
}

// Level returns the directory level
func (t DirectoryType) Level() uint {
	switch t {
	case PSPDirectoryLevel1:
		return 1
	case PSPDirectoryLevel2:
		return 2
	case BIOSDirectoryLevel1:
		return 1
	case BIOSDirectoryLevel2:
		return 2
	}
	panic(fmt.Sprintf("Not supported directory type: %d", t))
}

// DirectoryTypeFromString converts a string into DirectoryType
func DirectoryTypeFromString(in string) (DirectoryType, error) {
	for _, dt := range allDirectoryTypes {
		if strings.EqualFold(dt.ShortName(), in) {
			return dt, nil
		}
	}
	return 0, fmt.Errorf("unknown directory type: %s", in)
}

// GetPSPDirectoryOfLevel returns the PSP directory of a certain level
func GetPSPDirectoryOfLevel(level uint) (DirectoryType, error) {
	switch level {
	case 1:
		return PSPDirectoryLevel1, nil
	case 2:
		return PSPDirectoryLevel2, nil
	}
	return 0, fmt.Errorf("invalid PSP directory level: %d", level)
}

// GetBIOSDirectoryOfLevel returns the BIOS directory of a certain level
func GetBIOSDirectoryOfLevel(level uint) (DirectoryType, error) {
	switch level {
	case 1:
		return BIOSDirectoryLevel1, nil
	case 2:
		return BIOSDirectoryLevel2, nil
	}
	return 0, fmt.Errorf("invalid BIOS directory level: %d", level)
}

// GetBIOSEntries returns all entries of a certain type from BIOS directory sorted by instance
func GetBIOSEntries(
	pspFirmware *amd_manifest.PSPFirmware,
	biosLevel uint,
	entryID amd_manifest.BIOSDirectoryTableEntryType,
) ([]amd_manifest.BIOSDirectoryTableEntry, error) {
	biosTable, err := getBIOSTable(pspFirmware, biosLevel)
	if err != nil {
		return nil, err
	}

	if biosTable == nil {
		return nil, ErrNotFound{Item: fmt.Sprintf("BIOS directory of level %d", biosLevel)}
	}

	var biosTableEntries []amd_manifest.BIOSDirectoryTableEntry
	for _, entry := range biosTable.Entries {
		if entry.Type == entryID {
			biosTableEntries = append(biosTableEntries, entry)
		}
	}

	sort.Slice(biosTableEntries, func(i, j int) bool {
		return biosTableEntries[i].Instance < biosTableEntries[j].Instance
	})
	return biosTableEntries, nil
}

// GetBIOSEntry returns a singe entry of a certain type from BIOS directory, returns error if multiple entries are found
// if instance < 0 returns entry with any instnce
func GetBIOSEntry(
	pspFirmware *amd_manifest.PSPFirmware,
	biosLevel uint,
	entryID amd_manifest.BIOSDirectoryTableEntryType,
	instance int,
) (*amd_manifest.BIOSDirectoryTableEntry, error) {
	entries, err := GetBIOSEntries(pspFirmware, biosLevel, entryID)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, ErrNotFound{Item: fmt.Sprintf("No entries %x in BIOS directory level %d", entryID, biosLevel)}
	}
	if instance < 0 {
		if len(entries) != 1 {
			return nil, fmt.Errorf("multiple entriers %d are found in BIOS directory level %d", entryID, biosLevel)
		}
		return &entries[0], nil
	}

	var result *amd_manifest.BIOSDirectoryTableEntry
	for idx := range entries {
		if entries[idx].Instance == uint8(instance) {
			if result != nil {
				return nil, fmt.Errorf("multiple entriers %x of instance %d are found in BIOS directory level %d", entryID, instance, biosLevel)
			}
			result = &entries[idx]
		}
	}

	if result == nil {
		return nil, ErrNotFound{Item: fmt.Sprintf("No entries %x with instance %d in BIOS directory level %d", entryID, instance, biosLevel)}
	}
	return result, nil
}

// GetPSPEntries returns all entries of a certain type from PSP directory
func GetPSPEntries(
	pspFirmware *amd_manifest.PSPFirmware,
	pspLevel uint,
	entryID amd_manifest.PSPDirectoryTableEntryType,
) ([]amd_manifest.PSPDirectoryTableEntry, error) {
	pspTable, err := getPSPTable(pspFirmware, pspLevel)
	if err != nil {
		return nil, err
	}
	if pspTable == nil {
		return nil, ErrNotFound{Item: fmt.Sprintf("PSP directory of level %d", pspLevel)}
	}
	var entries []amd_manifest.PSPDirectoryTableEntry
	for _, entry := range pspTable.Entries {
		if entry.Type == entryID {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// GetPSPEntry returns a singe entry of a certain type from PSP directory, returns error if multiple entries are found
func GetPSPEntry(
	pspFirmware *amd_manifest.PSPFirmware,
	pspLevel uint,
	entryID amd_manifest.PSPDirectoryTableEntryType,
) (*amd_manifest.PSPDirectoryTableEntry, error) {
	entries, err := GetPSPEntries(pspFirmware, pspLevel, entryID)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, ErrNotFound{Item: fmt.Sprintf("No entries %x in PSP directory level %d", entryID, pspLevel)}
	}
	if len(entries) > 1 {
		return nil, fmt.Errorf("multiple entriers %x are found in PSP directory level %d", entryID, pspLevel)
	}
	return &entries[0], err
}

// GetEntries returns a list of specific type PSP entries
func GetEntries(pspFirmware *amd_manifest.PSPFirmware, directory DirectoryType, entryID uint32) ([]bytes2.Range, error) {
	var entries []bytes2.Range
	switch directory {
	case PSPDirectoryLevel1, PSPDirectoryLevel2:
		pspEntries, err := GetPSPEntries(pspFirmware, directory.Level(), amd_manifest.PSPDirectoryTableEntryType(entryID))
		if err != nil {
			return nil, err
		}

		for _, entry := range pspEntries {
			entries = append(entries, bytes2.Range{Offset: entry.LocationOrValue, Length: uint64(entry.Size)})
		}
	case BIOSDirectoryLevel1, BIOSDirectoryLevel2:
		biosEntries, err := GetBIOSEntries(pspFirmware, directory.Level(), amd_manifest.BIOSDirectoryTableEntryType(entryID))
		if err != nil {
			return nil, err
		}

		for _, entry := range biosEntries {
			entries = append(entries, bytes2.Range{Offset: entry.SourceAddress, Length: uint64(entry.Size)})
		}
	default:
		return nil, fmt.Errorf("unsopprted directory type: %s", directory)
	}
	return entries, nil
}

// GetRangeBytes converts firmware ragne to continues bytes sequence
// TODO: should be moved to fiano's bytes2
func GetRangeBytes(image []byte, start, length uint64) ([]byte, error) {
	end := start + length
	if err := checkBoundaries(start, end, image); err != nil {
		return nil, fmt.Errorf("boundary check fail: %w", err)
	}
	return image[start:end], nil
}

// ExtractPSPEntry extracts a single generic raw entry from PSP Directory.
// Returns an error if multiple entries are found as PSP directory is supposed to have no more than a single entry for each type
func ExtractPSPEntry(amdFw *amd_manifest.AMDFirmware, pspLevel uint, entryID amd_manifest.PSPDirectoryTableEntryType) ([]byte, error) {
	entry, err := GetPSPEntry(amdFw.PSPFirmware(), pspLevel, entryID)
	if err != nil {
		return nil, err
	}
	return GetRangeBytes(amdFw.Firmware().ImageBytes(), entry.LocationOrValue, uint64(entry.Size))
}

// ExtractBIOSEntry extracts a single generic raw entry from BIOS Directory.
func ExtractBIOSEntry(amdFw *amd_manifest.AMDFirmware, biosLevel uint, entryID amd_manifest.BIOSDirectoryTableEntryType, instance int) ([]byte, error) {
	entry, err := GetBIOSEntry(amdFw.PSPFirmware(), biosLevel, entryID, instance)
	if err != nil {
		return nil, err
	}
	return GetRangeBytes(amdFw.Firmware().ImageBytes(), entry.SourceAddress, uint64(entry.Size))
}

// DumpPSPEntry dumps an entry from PSP Directory
func DumpPSPEntry(amdFw *amd_manifest.AMDFirmware, pspLevel uint, entryID amd_manifest.PSPDirectoryTableEntryType, w io.Writer) (int, error) {
	data, err := ExtractPSPEntry(amdFw, pspLevel, entryID)
	if err != nil {
		return 0, err
	}
	return w.Write(data)
}

// DumpBIOSEntry dumps an entry from BIOS directory
func DumpBIOSEntry(amdFw *amd_manifest.AMDFirmware, biosLevel uint, entryID amd_manifest.BIOSDirectoryTableEntryType, instance int, w io.Writer) (int, error) {
	data, err := ExtractBIOSEntry(amdFw, biosLevel, entryID, instance)
	if err != nil {
		return 0, err
	}
	return w.Write(data)
}

// PatchPSPEntry takes an AmdFirmware object and modifies one entry in PSP directory.
// The modified entry is read from `r` reader object, while the modified firmware is written into `w` writer object.
func PatchPSPEntry(amdFw *amd_manifest.AMDFirmware, pspLevel uint, entryID amd_manifest.PSPDirectoryTableEntryType, r io.Reader, w io.Writer) (int, error) {
	entry, err := GetPSPEntry(amdFw.PSPFirmware(), pspLevel, entryID)
	if err != nil {
		return 0, err
	}

	start := entry.LocationOrValue
	end := start + uint64(entry.Size)
	return patchEntry(amdFw, start, end, r, w)
}

// PatchBIOSEntry takes an AmdFirmware object and modifies one entry in BIOS directory.
// The modified entry is read from `r` reader object, while the modified firmware is written into `w` writer object.
func PatchBIOSEntry(amdFw *amd_manifest.AMDFirmware, biosLevel uint, entryID amd_manifest.BIOSDirectoryTableEntryType, instance int, r io.Reader, w io.Writer) (int, error) {
	entry, err := GetBIOSEntry(amdFw.PSPFirmware(), biosLevel, entryID, instance)
	if err != nil {
		return 0, err
	}

	start := entry.SourceAddress
	end := start + uint64(entry.Size)
	return patchEntry(amdFw, start, end, r, w)
}

func patchEntry(amdFw *amd_manifest.AMDFirmware, start, end uint64, r io.Reader, w io.Writer) (int, error) {
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
