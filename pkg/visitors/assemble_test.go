// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"fmt"
	"testing"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/uefi"
)

var (
	ZeroGUID = guid.MustParse("00000000-0000-0000-0000-000000000000")
)

func TestBadDepex(t *testing.T) {
	var tests = []struct {
		name string
		op   uefi.DepExOp
		err  string
	}{
		{"badOpCode", uefi.DepExOp{OpCode: "BLAH", GUID: nil},
			"unable to map depex opcode string to opcode, string was: BLAH"},
		{"pushNoGUID", uefi.DepExOp{OpCode: "PUSH", GUID: nil},
			"depex opcode PUSH should not have nil guid"},
		{"trueWithGUID", uefi.DepExOp{OpCode: "TRUE", GUID: ZeroGUID},
			fmt.Sprintf("depex opcode TRUE should not have a guid! got %v", *ZeroGUID)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := &uefi.Section{}
			s.SetType(uefi.SectionTypeDXEDepEx)
			s.DepEx = []uefi.DepExOp{test.op}
			a := &Assemble{}
			err := a.Run(s)
			if err == nil {
				t.Fatalf("Expected error: %v, got nil!", test.err)
			}
			if errStr := err.Error(); test.err != errStr {
				t.Errorf("Expected error: %v, got %v instead", test.err, errStr)
			}
		})
	}
}
