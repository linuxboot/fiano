// Copyright 2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package psb

import (
	"fmt"

	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
)

// ParseAMDFirmware parses AMD firmware from the image bytes
func ParseAMDFirmware(image []byte) (*amd_manifest.AMDFirmware, error) {
	amdFw, err := amd_manifest.NewAMDFirmware(amd_manifest.FirmwareImage(image))
	if err != nil {
		return nil, fmt.Errorf("could not parse AMD Firmware: %w", err)
	}
	return amdFw, nil
}
