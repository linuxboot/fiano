package amd

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
	bytes2 "github.com/linuxboot/fiano/pkg/bytes"
)

// PSPTableType denotes specific firmware table in PSP firmware
type PSPTableType uint8

const (
	// PSPDirectoryLevel1 represents PSP directory table level 1
	PSPDirectoryLevel1 PSPTableType = iota
	// PSPDirectoryLevel2 represents PSP directory table level 2
	PSPDirectoryLevel2
	// BIOSDirectoryLevel1 represents BIOS directory table level 1
	BIOSDirectoryLevel1
	// BIOSDirectoryLevel2 represents BIOS directory table level 2
	BIOSDirectoryLevel2
)

func (t PSPTableType) String() string {
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

// ParseAMDFirmware parses AMD firmware from the image bytes
func ParseAMDFirmware(image []byte) (*amd_manifest.AMDFirmware, error) {
	firmware, err := uefi.ParseUEFIFirmwareBytes(image)
	if err != nil {
		return nil, fmt.Errorf("could not parse firmware image: %w", err)
	}
	amdFw, err := amd_manifest.NewAMDFirmware(firmware)
	if err != nil {
		return nil, fmt.Errorf("could not parse AMD Firmware: %w", err)
	}

	return amdFw, nil
}

// GetPSPEntries returns a list of specific type PSP entries
func GetPSPEntries(pspFirmware amd_manifest.PSPFirmware, table PSPTableType, entryID uint32) ([]bytes2.Range, error) {
	var entries []bytes2.Range
	switch table {
	case PSPDirectoryLevel1, PSPDirectoryLevel2:
		var pspTable *amd_manifest.PSPDirectoryTable
		if table == PSPDirectoryLevel1 {
			pspTable = pspFirmware.PSPDirectoryLevel1
		} else {
			pspTable = pspFirmware.PSPDirectoryLevel2
		}

		if pspTable == nil {
			return nil, ErrNotFound{Item: table.String()}
		}

		for _, entry := range pspTable.Entries {
			if entry.Type == amd_manifest.PSPDirectoryTableEntryType(entryID) {
				entries = append(entries, bytes2.Range{Offset: entry.LocationOrValue, Length: uint64(entry.Size)})
			}
		}
	case BIOSDirectoryLevel1, BIOSDirectoryLevel2:
		var biosTable *amd_manifest.BIOSDirectoryTable
		if table == BIOSDirectoryLevel1 {
			biosTable = pspFirmware.BIOSDirectoryLevel1
		} else {
			biosTable = pspFirmware.BIOSDirectoryLevel2
		}

		if biosTable == nil {
			return nil, ErrNotFound{Item: table.String()}
		}

		for _, entry := range biosTable.Entries {
			if entry.Type == amd_manifest.BIOSDirectoryTableEntryType(entryID) {
				entries = append(entries, bytes2.Range{Offset: entry.SourceAddress, Length: uint64(entry.Size)})
			}
		}
	default:
		return nil, fmt.Errorf("unsopprted directory type: %s", table)
	}
	return entries, nil
}
