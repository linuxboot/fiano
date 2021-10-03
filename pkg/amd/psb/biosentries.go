package psb

import (
	"fmt"

	amd_manifest "github.com/9elements/converged-security-suite/pkg/amd/manifest"
)

// extractRawBIOSEntry extracts data corresponding to an entry in the BIOS table
func extractRawBIOSEntry(id amd_manifest.BIOSDirectoryTableEntryType, pspFw *amd_manifest.PSPFirmware, firmware amd_manifest.Firmware) ([]byte, error) {

	if pspFw.BIOSDirectoryLevel1 == nil {
		return nil, fmt.Errorf("cannot extract raw BIOS Directory entry without BIOS Directory Level 1")
	}

	// TODO: add support for Level 2 directory
	for _, entry := range pspFw.BIOSDirectoryLevel1.Entries {
		if entry.Type == id {
			firmwareBytes := firmware.ImageBytes()
			start := entry.SourceAddress
			end := start + uint64(entry.Size)
			if err := checkBoundaries(start, end, firmwareBytes); err != nil {
				return nil, fmt.Errorf("cannot extract BIOS Directory entry from firmware image, boundary check fail: %w", err)
			}
			return firmwareBytes[start:end], nil
		}
	}
	return nil, fmt.Errorf("could not find BIOS directory entry %x in BIOS Directory Level 1", id)
}

// ValidateRTM validates signature of RTM volume and BIOS directory table concatenated
func ValidateRTM(firmware amd_manifest.Firmware) (*SignatureValidationResult, error) {

	amdFw, err := amd_manifest.NewAMDFirmware(firmware)
	if err != nil {
		return nil, fmt.Errorf("could not parse PSP firmware: %w", err)
	}

	pspFw := amdFw.PSPFirmware()

	// extract RTM Volume and signature
	rtmVolume, err := extractRawBIOSEntry(BIOSRTMVolumeEntry, pspFw, firmware)
	if err != nil {
		return nil, fmt.Errorf("could not extract BIOS entry corresponding to RTM volume (%x): %w", BIOSRTMVolumeEntry, err)
	}

	rtmVolumeSignature, err := extractRawBIOSEntry(BIOSRTMSignatureEntry, pspFw, firmware)
	if err != nil {
		return nil, fmt.Errorf("could not extract BIOS entry corresponding to RTM volume signature (%x): %w", BIOSRTMSignatureEntry, err)
	}

	keySet, err := GetKeys(firmware)
	if err != nil {
		return nil, fmt.Errorf("could not extract key from firmware: %w", err)
	}

	oemKeySet, err := keySet.KeysetFromType(OEMKey)
	if err != nil {
		return nil, fmt.Errorf("could not get keySet for type %s: %w", OEMKey, err)
	}

	// signature of RTM volume is calculated over the concatenation of RTM volume itself and
	// BIOS directory table
	firmwareBytes := firmware.ImageBytes()

	biosDirectoryStart := pspFw.BIOSDirectoryLevel1Range.Offset
	biosDirectoryEnd := biosDirectoryStart + pspFw.BIOSDirectoryLevel1Range.Length

	if err := checkBoundaries(biosDirectoryStart, biosDirectoryEnd, firmwareBytes); err != nil {
		return nil, fmt.Errorf("could not extract BIOS directory, boundary check error: %w", err)
	}

	biosDirectoryTableBytes := firmwareBytes[biosDirectoryStart:biosDirectoryEnd]
	rtmVolume = append(rtmVolume, biosDirectoryTableBytes...)

	_, key, err := NewMultiKeySignedBlob(reverse(rtmVolumeSignature), rtmVolume, oemKeySet, "RTM Volume concatenated with BIOS Directory")
	if err != nil {
		return nil, fmt.Errorf("could not validate signature of RTM Volume: %w", err)
	}

	return &SignatureValidationResult{signedElement: "RTM Volume concatenated with BIOS Directory", signingKey: key, err: nil}, nil
}
