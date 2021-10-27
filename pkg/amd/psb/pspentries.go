package psb

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"

	"github.com/jedib0t/go-pretty/v6/table"
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

// PSPEntryType defines the type to hold PSP Entry Type fields
type PSPEntryType uint8

/*
 * Nicely output human-readable names for PSP Entry Types
 *
 * This doesn't have all the entries mapped, there are still
 * several more pages left. It does have all the types
 * encountered in the firmware images used to test
 * however.
 *
 */
func (_type PSPEntryType) String() string {
	switch _type {
	case 0x00:
		return "AMD_PUBLIC_KEYS"
	case 0x01:
		return "PSP_BOOT_LOADER"
	case 0x02:
		return "PSP_SECURE_OS"
	case 0x03:
		return "PSP_RECOVERY_BOOTLOADER"
	case 0x04:
		return "PSP_NON_VOLATILE_DATA"
	case 0x08:
		return "SMU_OFF_CHIP_FIRMWARE"
	case 0x09:
		return "AMD_SECURE_DEBUG_KEY"
	case 0x0A:
		return "ABL_PUBLIC_KEY"
	case 0x0B:
		return "PSP_SOFT_FUSE_CHAIN"
	case 0x0C:
		return "PSP_BOOT_LOADED_TRUSTLETS"
	case 0x0D:
		return "PSP_TRUSTLET_PUBLIC_KEY"
	case 0x12:
		return "SMU_OFF_CHIP_FIRMWARE"
	case 0x13:
		return "UNLOCK_DEBUG_IMAGE"
	case 0x20:
		return "IP_DISCOVERY_BINARY"
	case 0x21:
		return "WRAPPED_IKEK"
	case 0x22:
		return "PSP_TOKEN_UNLOCK_DATA"
	case 0x24:
		return "SEC_POLICY_BINARY"
	case 0x25:
		return "MP2_FIRMWARE"
	case 0x26:
		return "MP2_FIRMWARE_PART_TWO"
	case 0x27:
		return "USER_MODE_UNIT_TESTS"
	case 0x28:
		return "SYSTEM_DRIVER_IN_SPI"
	case 0x29:
		return "KVM_IMAGE"
	case 0x2A:
		return "MP5_FIRMWARE"
	case 0x2B:
		return "EMBEDDED_FIRMWARE_STRUCTURE"
	case 0x2C:
		return "TEE_WRITE_ONCE_NVRAM"
	case 0x2D:
		return "EXTERNAL_PSP_BOOTLOADER"
	case 0x2E:
		return "EXTERNAL_MP0"
	case 0x2F:
		return "EXTERNAL_MP1"
	case 0x30:
		return "AGESA_BINARY_0"
	case 0x31:
		return "AGESA_BINARY_1"
	case 0x32:
		return "AGESA_BINARY_2"
	case 0x33:
		return "AGESA_BINARY_3"
	case 0x34:
		return "AGESA_BINARY_4"
	case 0x35:
		return "AGESA_BINARY_5"
	case 0x36:
		return "AGESA_BINARY_6"
	case 0x37:
		return "AGESA_BINARY_7"
	case 0x38:
		return "SEV_DATA"
	case 0x39:
		return "SEV_CODE"
	case 0x3A:
		return "PROCESSOR_SERIAL_WHITELIST"
	case 0x3B:
		return "SERDES_MICROCODE"
	case 0x3C:
		return "VBIOS_PRELOAD"
	case 0x3D:
		return "WLAN_UMAC"
	case 0x3E:
		return "WLAN_IMAC"
	case 0x3F:
		return "WLAN_BLUETOOTH"
	case 0x40:
		return "PSP_DIRECTORY_LEVEL_2"
	case 0x41:
		return "EXTERNAL_MP0_BOOTLOADER"
	case 0x42:
		return "EXTERNAL_DXIO_SRAM_FIRMWARE"
	case 0x43:
		return "EXTERNAL_DXIO_SRAM_PUBLIC_KEY"
	case 0x44:
		return "USB_UNIFIED_PHY_FIRMWARE"
	case 0x45:
		return "SEC_POLICY_BINARY_TOS"
	case 0x46:
		return "EXTERNAL_PSP_BOOTLOADER"
	case 0x47:
		return "DRTM_TA"
	// ... skipped entries ...
	case 0x50:
		return "SPI_ROM_PUBLIC_KEYS"
	}
	return "UNKNOWN"
}

func getPSPTable(amdFw *amd_manifest.AMDFirmware, pspLevel uint) (*amd_manifest.PSPDirectoryTable, error) {
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

	return pspDirectory, nil
}

// OutputPSPEntries outputs the PSP entries in an ASCII table format
func OutputPSPEntries(amdFw *amd_manifest.AMDFirmware) error {

	pspDirectoryLevel1Table, err := getPSPTable(amdFw, 1)
	if err != nil {
		return fmt.Errorf("unable to retrieve PSP Directory Level 1 Entries: %w", err)
	}

	pspDirectoryLevel2Table, err := getPSPTable(amdFw, 2)
	if err != nil {
		return fmt.Errorf("unable to retrieve PSP Directory Level 2 Entries: %w", err)
	}

	pspDirectories := []amd_manifest.PSPDirectoryTable{*pspDirectoryLevel1Table, *pspDirectoryLevel2Table}

	for idx, directory := range pspDirectories {
		// PSP Header
		h := table.NewWriter()
		h.SetOutputMirror(os.Stdout)
		h.SetTitle("PSP Directory Level %d Header", idx+1)
		pspCookie := fmt.Sprintf("0x%x", directory.PSPCookie)
		pspChecksum := directory.Checksum
		pspTotalEntries := directory.TotalEntries
		pspAdditionalInfo := fmt.Sprintf("0x%x", directory.AdditionalInfo)
		h.AppendHeader(table.Row{"PSP Cookie", "Checksum", "Total Entries", "Additional Info"})
		h.AppendRow([]interface{}{pspCookie, pspChecksum, pspTotalEntries, pspAdditionalInfo})
		h.Render()

		// PSP Entries
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.SetTitle("PSP Directory Level %d", idx+1)
		t.AppendHeader(table.Row{"Type", "Hex Type", "SubProgram", "ROM ID", "Size", "Location/Value"})
		for _, entry := range directory.Entries {
			entryType := PSPEntryType(entry.Type)
			entryTypeHex := fmt.Sprintf("0x%-3x", entry.Type)
			entrySubprogram := fmt.Sprintf("0x%-8x", entry.Subprogram)
			entryRomID := fmt.Sprintf("0x%-3x", entry.ROMId)
			entrySize := fmt.Sprintf("%-10d", entry.Size)
			entryLocation := fmt.Sprintf("0x%-10x", entry.LocationOrValue)
			t.AppendRow([]interface{}{entryType, entryTypeHex, entrySubprogram, entryRomID, entrySize, entryLocation})
		}
		t.Render()
	}
	return nil
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

		data, err := extractRawEntry(amdFw, pspLevel, "psp", uint64(id))
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
