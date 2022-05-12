package psb

import (
	"fmt"
	"os"

	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
	bytes2 "github.com/linuxboot/fiano/pkg/bytes"

	"github.com/jedib0t/go-pretty/v6/table"
)

// BIOSEntryType defines the type to hold BIOS Entry Type fields
type BIOSEntryType uint8

/*
 * Nicely output human-readable names for BIOS Entry Types
 *
 * This doesn't have all the entries mapped, there are still
 * several more pages left. It does have all the types
 * encountered in the firmware images used to test
 * however.
 *
 */
func (_type BIOSEntryType) String() string {
	switch _type {
	case 0x05:
		return "BIOS_PUBLIC_KEY"
	case 0x07:
		return "BIOS_RTM_SIGNATURE"
	case 0x60:
		return "AGESA_PSP_CUSTOMIZATION_BLOCK"
	case 0x61:
		return "AGESA_PSP_OUTPUT_BLOCK"
	case 0x62:
		return "BIOS_BINARY"
	case 0x63:
		return "AGESA_PSP_OUTPUT_BLOCK_NV_COPY"
	case 0x64:
		return "PMU_FIRMWARE_INSTRUCTION_PORTION"
	case 0x65:
		return "PMU_FIRMWARE_DATA_PORTION"
	case 0x66:
		return "MICROCODE_PATCH"
	case 0x67:
		return "CORE_MACHINE_EXCEPTION_DATA"
	case 0x68:
		return "BACKUP_AGESA_PSP_CUSTOMIZATION_BLOCK"
	case 0x69:
		return "INTERPRETER_BINARY_VIDEO"
	case 0x6A:
		return "MP2_FIRMWARE_CONFIG"
	case 0x6B:
		return "MAIN_MEMORY"
	case 0x6C:
		return "MPM_CONFIG"
	case 0x70:
		return "BIOS_DIRECTORY_TABLE_LEVEL_2"
	}
	return "UNKNOWN"

}

func getBIOSTable(pspFirmware *amd_manifest.PSPFirmware, biosLevel uint) (*amd_manifest.BIOSDirectoryTable, error) {
	switch biosLevel {
	case 1:
		return pspFirmware.BIOSDirectoryLevel1, nil
	case 2:
		return pspFirmware.BIOSDirectoryLevel2, nil
	}
	return nil, fmt.Errorf("cannot extract key database, invalid BIOS Directory Level requested: %d", biosLevel)
}

// OutputBIOSEntries outputs the BIOS entries in an ASCII table format
func OutputBIOSEntries(amdFw *amd_manifest.AMDFirmware) error {
	biosDirectoryLevel1Table, err := getBIOSTable(amdFw.PSPFirmware(), 1)
	if err != nil {
		return fmt.Errorf("unable to retrieve BIOS Directory Level 1 Entries: %w", err)
	}

	biosDirectoryLevel2Table, err := getBIOSTable(amdFw.PSPFirmware(), 2)
	if err != nil {
		return fmt.Errorf("unable to retrieve BIOS Directory Level 2 Entries: %w", err)
	}

	biosDirectories := []amd_manifest.BIOSDirectoryTable{*biosDirectoryLevel1Table, *biosDirectoryLevel2Table}

	for idx, directory := range biosDirectories {
		// BIOS Header
		h := table.NewWriter()
		h.SetOutputMirror(os.Stdout)
		h.SetTitle("BIOS Directory Level %d Header", idx+1)
		biosCookie := fmt.Sprintf("0x%x", directory.BIOSCookie)
		biosChecksum := directory.Checksum
		biosTotalEntries := directory.TotalEntries
		h.AppendHeader(table.Row{"BIOS Cookie", "Checksum", "Total Entries"})
		h.AppendRow([]interface{}{biosCookie, biosChecksum, biosTotalEntries})
		h.Render()

		// BIOS Entries
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.SetTitle("BIOS Directory Level %d", idx+1)
		t.AppendHeader(table.Row{
			"Type",
			"Type Hex",
			"RegionType",
			"ResetImage",
			"CopyImage",
			"ReadOnly",
			"Compressed",
			"Instance",
			"Subprogram",
			"RomID",
			"Size",
			"Source Address",
			"Destination Address",
		})
		for _, entry := range directory.Entries {
			entryType := BIOSEntryType(entry.Type)
			entryTypeHex := fmt.Sprintf("0x%-3x", entry.Type)
			entryRegionType := fmt.Sprintf("0x%-8x", entry.RegionType)
			entryResetImage := fmt.Sprintf("%-10v", entry.ResetImage)
			entryCopyImage := fmt.Sprintf("%-9v", entry.CopyImage)
			entryReadOnly := fmt.Sprintf("%-8v", entry.ReadOnly)
			entryCompressed := fmt.Sprintf("%-10v", entry.Compressed)
			entryInstance := fmt.Sprintf("0x%-6x", entry.Instance)
			entrySubprogram := fmt.Sprintf("0x%-8x", entry.Subprogram)
			entryRomID := fmt.Sprintf("0x%-3x", entry.RomID)
			entrySize := fmt.Sprintf("%-6d", entry.Size)
			entrySourceAddress := fmt.Sprintf("0x%-11x", entry.SourceAddress)
			entryDestinationAddress := fmt.Sprintf("0x%-18x", entry.DestinationAddress)
			t.AppendRow([]interface{}{
				entryType,
				entryTypeHex,
				entryRegionType,
				entryResetImage,
				entryCopyImage,
				entryReadOnly,
				entryCompressed,
				entryInstance,
				entrySubprogram,
				entryRomID,
				entrySize,
				entrySourceAddress,
				entryDestinationAddress,
			})
		}
		t.Render()
	}
	return nil
}

// ValidateRTM validates signature of RTM volume and BIOS directory table concatenated
func ValidateRTM(amdFw *amd_manifest.AMDFirmware, biosLevel uint) (*SignatureValidationResult, error) {

	pspFw := amdFw.PSPFirmware()

	// Get the byte range we'll need on the BIOS depending on the level
	var biosDirectoryRange bytes2.Range
	switch biosLevel {
	case 1:
		biosDirectoryRange = pspFw.BIOSDirectoryLevel1Range
	case 2:
		biosDirectoryRange = pspFw.BIOSDirectoryLevel2Range
	default:
		return nil, fmt.Errorf("cannot extract raw BIOS entry, invalid BIOS Directory Level requested: %d", biosLevel)
	}

	// extract RTM Volume and signature
	rtmVolume, err := ExtractBIOSEntry(amdFw, biosLevel, BIOSRTMVolumeEntry, 0)
	if err != nil {
		return nil, fmt.Errorf("could not extract BIOS entry corresponding to RTM volume (%x): %w", BIOSRTMVolumeEntry, err)
	}

	rtmVolumeSignature, err := ExtractBIOSEntry(amdFw, biosLevel, BIOSRTMSignatureEntry, 0)
	if err != nil {
		return nil, fmt.Errorf("could not extract BIOS entry corresponding to RTM volume signature (%x): %w", BIOSRTMSignatureEntry, err)
	}

	keySet, err := GetKeys(amdFw, biosLevel)
	if err != nil {
		return nil, fmt.Errorf("could not extract key from firmware: %w", err)
	}

	oemKeySet, err := keySet.KeysetFromType(OEMKey)
	if err != nil {
		return nil, fmt.Errorf("could not get keySet for type %s: %w", OEMKey, err)
	}

	// signature of RTM volume is calculated over the concatenation of RTM volume itself and
	// BIOS directory table
	firmwareBytes := amdFw.Firmware().ImageBytes()

	biosDirectoryStart := biosDirectoryRange.Offset
	biosDirectoryEnd := biosDirectoryStart + biosDirectoryRange.Length

	if err := checkBoundaries(biosDirectoryStart, biosDirectoryEnd, firmwareBytes); err != nil {
		return nil, fmt.Errorf("could not extract BIOS Level %d directory, boundary check error: %w", biosLevel, err)
	}

	/**
	 * This is needed due to the fact in the Level 2 BIOS Directory Table,
	 * instead of RTM Volume + Level 2 Header for the signed data, it's actually
	 * RTM Volume + Level 1 Header + Level 2 Header
	 */
	if biosLevel == 2 {
		biosDirectoryLevel1Start := pspFw.BIOSDirectoryLevel1Range.Offset
		biosDirectoryLevel1End := biosDirectoryLevel1Start + pspFw.BIOSDirectoryLevel1Range.Length

		if err := checkBoundaries(biosDirectoryLevel1Start, biosDirectoryLevel1End, firmwareBytes); err != nil {
			return nil, fmt.Errorf("could not extract BIOS Level 1 directory, boundary check error: %w", err)
		}

		biosDirectoryTableBytes := firmwareBytes[biosDirectoryLevel1Start:biosDirectoryLevel1End]
		rtmVolume = append(rtmVolume, biosDirectoryTableBytes...)
	}

	biosDirectoryTableBytes := firmwareBytes[biosDirectoryStart:biosDirectoryEnd]
	rtmVolume = append(rtmVolume, biosDirectoryTableBytes...)

	_, key, err := NewMultiKeySignedBlob(reverse(rtmVolumeSignature), rtmVolume, oemKeySet, "RTM Volume concatenated with BIOS Directory")
	if err != nil {
		return nil, fmt.Errorf("could not validate signature of RTM Volume: %w", err)
	}

	return &SignatureValidationResult{signedElement: "RTM Volume concatenated with BIOS Directory", signingKey: key, err: nil}, nil
}
