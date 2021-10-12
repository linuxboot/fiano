package psb

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	amd_manifest "github.com/9elements/converged-security-suite/pkg/amd/manifest"
)

const (
	// AMDPublicKeyEntry denotes AMD public key entry in PSP Directory table
	AMDPublicKeyEntry amd_manifest.PSPDirectoryTableEntryType = 0x00

	// KeyDatabaseEntry points to region of firmware containing key database
	KeyDatabaseEntry amd_manifest.PSPDirectoryTableEntryType = 0x50

	// ABLPublicKey represents the key used to sign ABL firmware
	ABLPublicKey amd_manifest.PSPDirectoryTableEntryType = 0x0A

	// OEMSigningKeyEntry represents the OEM signing key
	OEMSigningKeyEntry amd_manifest.BIOSDirectoryTableEntryType = 0x05

	// BIOSRTMVolumeEntry represents the RTM volume
	BIOSRTMVolumeEntry amd_manifest.BIOSDirectoryTableEntryType = 0x62

	// BIOSRTMSignatureEntry represents the entry holding the RTM volume signature
	BIOSRTMSignatureEntry amd_manifest.BIOSDirectoryTableEntryType = 0x07
)

// extractRawPSPEntry extracts data corresponding to an entry in the PSP table. We assume
// to look-up for the entry in the level 1 directory.
func extractRawPSPEntry(id amd_manifest.PSPDirectoryTableEntryType, amdFw *amd_manifest.AMDFirmware, pspLevel uint) ([]byte, error) {
	var pspDirectory *amd_manifest.PSPDirectoryTable

	pspFw := amdFw.PSPFirmware()

	switch pspLevel {
	case 1:
		pspDirectory = pspFw.PSPDirectoryLevel1
	case 2:
		pspDirectory = pspFw.PSPDirectoryLevel2
	default:
		return nil, fmt.Errorf("cannot extract raw PSP entry, invalid PSP Directory Level requested: %d", pspLevel)
	}

	for _, entry := range pspDirectory.Entries {
		if entry.Type == id {
			firmwareBytes := amdFw.Firmware().ImageBytes()
			start := entry.LocationOrValue
			end := start + uint64(entry.Size)
			if err := checkBoundaries(start, end, firmwareBytes); err != nil {
				return nil, fmt.Errorf("cannot extract PSP entry %x from firmware image, boundary check fail: %w", id, err)
			}
			return firmwareBytes[start:end], nil
		}
	}
	return nil, fmt.Errorf("could not find PSP entry %x in PSP Directory Level %d", id, pspLevel)
}

// ValidatePSPEntries validates signature of PSP entries given their entry values in PSP Table
func ValidatePSPEntries(amdFw *amd_manifest.AMDFirmware, pspLevel uint, entries []string) ([]SignatureValidationResult, error) {

	keyDB, err := GetKeys(amdFw, pspLevel)
	if err != nil {
		return nil, fmt.Errorf("could not extract key database: %w", err)
	}

	validationResults := make([]SignatureValidationResult, 0, len(entries))

	for _, entry := range entries {
		id, err := strconv.ParseInt(entry, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("could not parse hexadecimal entry: %w", err)
		}

		data, err := extractRawPSPEntry(amd_manifest.PSPDirectoryTableEntryType(id), amdFw, pspLevel)
		if err != nil {
			return nil, fmt.Errorf("could not extract entry 0x%x from PSP table: %w", id, err)
		}
		binary, err := newPSPBinary(data)
		if err != nil {
			return nil, fmt.Errorf("could not create PSB binary from raw data for entry 0x%x: %w", entry, err)
		}
		signedBlob, err := binary.getSignedBlob(keyDB)
		var signedElement strings.Builder
		fmt.Fprintf(&signedElement, "PSP entry 0x%s", entry)

		if err != nil {
			var sigError *SignatureCheckError
			if errors.As(err, &sigError) {
				validationResults = append(validationResults, SignatureValidationResult{signedElement: signedElement.String(), signingKey: sigError.SigningKey(), err: err})
			} else {
				validationResults = append(validationResults, SignatureValidationResult{signedElement: signedElement.String(), err: err})
			}
		} else {
			signature := signedBlob.Signature()
			validationResults = append(validationResults, SignatureValidationResult{signedElement: signedElement.String(), signingKey: signature.SigningKey(), err: err})
		}

	}

	return validationResults, nil
}

// DumpPSPEntry dump an entry to a file on the filesystem
func DumpPSPEntry(amdFw *amd_manifest.AMDFirmware, pspLevel uint, entry string, entryFile string) (int, error) {

	id, err := strconv.ParseInt(entry, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("could not parse hexadecimal entry: %w", err)
	}

	data, err := extractRawPSPEntry(amd_manifest.PSPDirectoryTableEntryType(id), amdFw, pspLevel)
	if err != nil {
		return 0, fmt.Errorf("could not extract entry 0x%x from PSP table: %w", id, err)
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

//PatchPSPEntry take a path on the filesystem pointing to a dump of a PSP entry and re-apply it to the firmware
func PatchPSPEntry(amdFw *amd_manifest.AMDFirmware, pspLevel uint, entry string, entryFile string, modifiedFirmwareFile string) (int, error) {
	//read firmware

	id, err := strconv.ParseInt(entry, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("could not parse hexadecimal entry: %w", err)
	}

	var pspDirectory *amd_manifest.PSPDirectoryTable

	pspFw := amdFw.PSPFirmware()

	switch pspLevel {
	case 1:
		pspDirectory = pspFw.PSPDirectoryLevel1
	case 2:
		pspDirectory = pspFw.PSPDirectoryLevel2
	default:
		return 0, fmt.Errorf("cannot extract key database, invalid PSP Directory Level requested: %d", pspLevel)
	}

	modifiedEntry, err := os.ReadFile(entryFile)
	if err != nil {
		return 0, fmt.Errorf("could not read Modified entry: %w", err)
	}
	var n int = 0

	for _, entry := range pspDirectory.Entries {
		if entry.Type == amd_manifest.PSPDirectoryTableEntryType(id) {
			firmwareBytes := amdFw.Firmware().ImageBytes()
			start := entry.LocationOrValue
			end := start + uint64(entry.Size)
			if err := checkBoundaries(start, end, firmwareBytes); err != nil {
				return 0, fmt.Errorf("cannot extract key database from firmware image, boundary check fail: %w", err)
			}

			if uint64(entry.Size) != uint64(len(modifiedEntry)) {
				return 0, fmt.Errorf("cannot write the entry to the firmware image, entry size check fail, expected %d, modified entry is %d", uint64(entry.Size), uint64(len(modifiedEntry)))
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
	}
	return n, nil
}
