// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"testing"
)

func TestCount(t *testing.T) {
	f := parseImage(t)

	count := &Count{}
	if err := count.Run(f); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		mapPtr       *map[string]int
		firmwareType string
		atLeast      int
	}{
		{&count.FirmwareTypeCount, "BIOSRegion", 1},
		{&count.FirmwareTypeCount, "File", 2},
		{&count.FirmwareTypeCount, "FirmwareVolume", 2},
		{&count.FirmwareTypeCount, "Section", 2},
		{&count.FileTypeCount, "EFI_FV_FILETYPE_APPLICATION", 2},
		{&count.FileTypeCount, "EFI_FV_FILETYPE_DRIVER", 2},
		{&count.FileTypeCount, "EFI_FV_FILETYPE_DXE_CORE", 1},
		{&count.FileTypeCount, "EFI_FV_FILETYPE_FFS_PAD", 1},
		{&count.FileTypeCount, "EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE", 1},
		{&count.FileTypeCount, "EFI_FV_FILETYPE_FREEFORM", 1},
		{&count.FileTypeCount, "EFI_FV_FILETYPE_PEIM", 1},
		{&count.FileTypeCount, "EFI_FV_FILETYPE_PEI_CORE", 1},
		{&count.FileTypeCount, "EFI_FV_FILETYPE_RAW", 1},
		{&count.FileTypeCount, "EFI_FV_FILETYPE_SECURITY_CORE", 1},
		{&count.SectionTypeCount, "EFI_SECTION_DXE_DEPEX", 2},
		{&count.SectionTypeCount, "EFI_SECTION_FIRMWARE_VOLUME_IMAGE", 1},
		{&count.SectionTypeCount, "EFI_SECTION_GUID_DEFINED", 1},
		{&count.SectionTypeCount, "EFI_SECTION_PE32", 2},
		{&count.SectionTypeCount, "EFI_SECTION_RAW", 2},
		{&count.SectionTypeCount, "EFI_SECTION_USER_INTERFACE", 2},
		{&count.SectionTypeCount, "EFI_SECTION_VERSION", 2},
	}

	for _, tt := range tests {
		t.Run(tt.firmwareType, func(t *testing.T) {
			if _, ok := (*tt.mapPtr)[tt.firmwareType]; !ok {
				t.Fatalf("expected %q to be in the count", tt.firmwareType)
			}
			if (*tt.mapPtr)[tt.firmwareType] < tt.atLeast {
				t.Fatalf("expected to count at least %d of type %q, got %d",
					tt.atLeast, tt.firmwareType, (*tt.mapPtr)[tt.firmwareType])
			}

		})
	}
}
