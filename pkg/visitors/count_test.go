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
		firmwareType string
		atLeast      int
	}{
		{"BIOSRegion", 1},
		{"File", 2},
		{"FirmwareVolume", 2},
		{"Section", 2},
	}

	for _, tt := range tests {
		t.Run(tt.firmwareType, func(t *testing.T) {
			if _, ok := count.Count[tt.firmwareType]; !ok {
				t.Fatalf("expected %q to be in the count", tt.firmwareType)
			}
			if count.Count[tt.firmwareType] < tt.atLeast {
				t.Fatalf("expected to count at least %d of type %q, got %d",
					tt.atLeast, tt.firmwareType, count.Count[tt.firmwareType])
			}

		})
	}
}
