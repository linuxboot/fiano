package psb

import (
	"fmt"

	amd_manifest "github.com/9elements/converged-security-suite/pkg/amd/manifest"
	bytes2 "github.com/9elements/converged-security-suite/pkg/bytes"
)

// extractRawBIOSEntry extracts data corresponding to an entry in the BIOS table
func extractRawBIOSEntry(id amd_manifest.BIOSDirectoryTableEntryType, biosLevel uint, amdFw *amd_manifest.AMDFirmware) ([]byte, error) {

	var biosDirectory *amd_manifest.BIOSDirectoryTable

	pspFw := amdFw.PSPFirmware()

	switch biosLevel {
	case 1:
		biosDirectory = pspFw.BIOSDirectoryLevel1
	case 2:
		biosDirectory = pspFw.BIOSDirectoryLevel2
	default:
		return nil, fmt.Errorf("cannot extract key database, invalid BIOS Directory Level requested: %d", biosLevel)
	}

	for _, entry := range biosDirectory.Entries {
		if entry.Type == id {
			firmwareBytes := amdFw.Firmware().ImageBytes()
			start := entry.SourceAddress
			end := start + uint64(entry.Size)
			if err := checkBoundaries(start, end, firmwareBytes); err != nil {
				return nil, fmt.Errorf("cannot extract BIOS Directory entry from firmware image, boundary check fail: %w", err)
			}
			return firmwareBytes[start:end], nil
		}
	}
	return nil, fmt.Errorf("could not find BIOS directory entry %x in BIOS Directory Level %d", id, biosLevel)
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
	rtmVolume, err := extractRawBIOSEntry(BIOSRTMVolumeEntry, biosLevel, amdFw)
	if err != nil {
		return nil, fmt.Errorf("could not extract BIOS entry corresponding to RTM volume (%x): %w", BIOSRTMVolumeEntry, err)
	}

	rtmVolumeSignature, err := extractRawBIOSEntry(BIOSRTMSignatureEntry, biosLevel, amdFw)
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
