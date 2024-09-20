// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"testing"

	utk_test "github.com/linuxboot/fiano/integration"
	"github.com/linuxboot/fiano/pkg/uefi"
)

func TestValidateFV(t *testing.T) {
	var tests = []struct {
		name string
		buf  []byte
		msgs []string
	}{
		{"sampleFV", utk_test.OVMFSecFV, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fv, err := uefi.NewFirmwareVolume(test.buf, 0, false)
			if err != nil {
				t.Fatalf("Error was not expected, got %v", err.Error())
			}
			v := &Validate{}
			if err := v.Run(fv); err != nil {
				t.Fatal(err)
			}
			if len(v.Errors) != len(test.msgs) {
				t.Errorf("Errors mismatched, wanted \n%v\n, got \n%v\n", test.msgs, v.Errors)
			} else {
				for i := range v.Errors {
					if v.Errors[i].Error() != test.msgs[i] {
						t.Errorf("Error mismatched, wanted \n%v\n, got \n%v\n", test.msgs[i], v.Errors[i].Error())
					}
				}
			}
		})
	}
}

func TestValidateFile(t *testing.T) {
	var tests = []struct {
		name string
		buf  []byte
		msgs []string
	}{
		{"emptyPadFile", emptyPadFile, nil},
		{"badFreeFormFile", badFreeFormFile, []string{"file FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF header checksum failure! sum was 54"}},
		{"goodFreeFormFile", goodFreeFormFile, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, err := uefi.NewFile(test.buf)
			if err != nil {
				t.Fatalf("Error was not expected, got %v", err.Error())
			}
			v := &Validate{}
			if err := v.Run(f); err != nil {
				t.Fatal(err)
			}
			if len(v.Errors) != len(test.msgs) {
				t.Errorf("Errors mismatched, wanted \n%v\n, got \n%v\n", test.msgs, v.Errors)
			} else {
				for i := range v.Errors {
					if v.Errors[i].Error() != test.msgs[i] {
						t.Errorf("Error mismatched, wanted \n%v\n, got \n%v\n", test.msgs[i], v.Errors[i].Error())
					}
				}
			}
		})
	}
}
