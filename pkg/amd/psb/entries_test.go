package psb

import (
	"strings"
	"testing"

	"privatecore/firmware/samples"

	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
	"github.com/stretchr/testify/require"
)

func TestDirectoryType(t *testing.T) {
	require.Equal(t, allDirectoryTypes, AllDirectoryTypes())
	require.NotEmpty(t, allDirectoryTypes)

	for _, directory := range allDirectoryTypes {
		t.Run(directory.ShortName(), func(t *testing.T) {
			require.NotEmpty(t, directory.ShortName())
			require.NotEmpty(t, directory.String())
			resDirectory, err := DirectoryTypeFromString(strings.ToUpper(directory.ShortName()))
			require.NoError(t, err)
			require.Equal(t, directory, resDirectory)

			resDirectory, err = DirectoryTypeFromString(strings.ToLower(directory.ShortName()))
			require.NoError(t, err)
			require.Equal(t, directory, resDirectory)
		})
	}

	_, err := DirectoryTypeFromString("No such directory type")
	require.Error(t, err)
}

func TestGetPSPEntry(t *testing.T) {
	firmwareImage, err := samples.GetFile("firmwares", "F09C_3B08.bin.xz")
	require.NoError(t, err)

	fw, err := uefi.ParseUEFIFirmwareBytes(firmwareImage)
	require.NoError(t, err)
	amdFw, err := amd_manifest.NewAMDFirmware(fw)
	require.NoError(t, err)

	t.Run("item_found", func(t *testing.T) {
		item, err := GetPSPEntry(amdFw.PSPFirmware(), 1, AMDPublicKeyEntry)
		require.NoError(t, err)
		require.NotNil(t, item)
	})

	t.Run("item_not_found", func(t *testing.T) {
		item, err := GetPSPEntry(amdFw.PSPFirmware(), 2, AMDPublicKeyEntry)
		var errNotFound ErrNotFound
		require.ErrorAs(t, err, &errNotFound)
		pspEntryItem := errNotFound.GetItem().(PSPDirectoryEntryItem)
		require.Equal(t, AMDPublicKeyEntry, pspEntryItem.Entry)
		require.Equal(t, uint8(2), pspEntryItem.Level)
		require.Nil(t, item)
	})
}

func TestGetBIOSEntry(t *testing.T) {
	firmwareImage, err := samples.GetFile("firmwares", "F09C_3B08.bin.xz")
	require.NoError(t, err)

	fw, err := uefi.ParseUEFIFirmwareBytes(firmwareImage)
	require.NoError(t, err)
	amdFw, err := amd_manifest.NewAMDFirmware(fw)
	require.NoError(t, err)

	t.Run("item_found", func(t *testing.T) {
		item, err := GetBIOSEntry(amdFw.PSPFirmware(), 2, amd_manifest.BIOSRTMVolumeEntry, 0)
		require.NoError(t, err)
		require.NotNil(t, item)
	})

	t.Run("item_not_found", func(t *testing.T) {
		item, err := GetBIOSEntry(amdFw.PSPFirmware(), 2, amd_manifest.BIOSRTMVolumeEntry, 1)
		var errNotFound ErrNotFound
		require.ErrorAs(t, err, &errNotFound)
		biosEntryItem := errNotFound.GetItem().(BIOSDirectoryEntryItem)
		require.Equal(t, amd_manifest.BIOSRTMVolumeEntry, biosEntryItem.Entry)
		require.Equal(t, uint8(2), biosEntryItem.Level)
		require.Equal(t, uint8(1), biosEntryItem.Instance)
		require.Nil(t, item)
	})
}
