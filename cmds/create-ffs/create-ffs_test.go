// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/uefi"
)

func compareErrors(expected string, err error) error {
	if expected != "" {
		if err == nil {
			return fmt.Errorf("error was not returned, expected %v", expected)
		}
		if expected != err.Error() {
			return fmt.Errorf("mismatched error returned, expected \n%v\n got \n%v",
				expected, err.Error())
		}
	} else if err != nil {
		return fmt.Errorf("error was not expected, got %v", err)
	}
	return nil
}

func compareOps(expectedOps []uefi.DepExOp, ops []uefi.DepExOp) error {
	if expectedOps != nil {
		if ops == nil {
			return fmt.Errorf("expected ops: %v, got nil", expectedOps)
		}
		if elen, olen := len(expectedOps), len(ops); elen != olen {
			return fmt.Errorf("different lenghts of depexes expected \n%v\n got \n%v",
				elen, olen)
		}
		for i := range expectedOps {
			if expectedOps[i].OpCode != ops[i].OpCode {
				return fmt.Errorf("different opcodes! expected %v, got %v",
					expectedOps[i].OpCode, ops[i].OpCode)
			}
			if expectedOps[i].GUID != nil {
				if ops[i].GUID == nil {
					return fmt.Errorf("expected GUID %v, got nil",
						*expectedOps[i].GUID)
				}
				if *expectedOps[i].GUID != *ops[i].GUID {
					return fmt.Errorf("mismatched GUID, expected %v, got %v",
						*expectedOps[i].GUID, *ops[i].GUID)
				}
			} else if ops[i].GUID != nil {
				return fmt.Errorf("expected no GUIDs, got %v", *ops[i].GUID)
			}
		}
	} else if ops != nil {
		return fmt.Errorf("expected no ops, got %v", ops)
	}
	return nil
}

func TestCreateDepExes(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		ops   []uefi.DepExOp
		msg   string
	}{
		{"trueDepEx", "TRUE", []uefi.DepExOp{{OpCode: "TRUE"}, {OpCode: "END"}}, ""},
		{"pushone", "01234567-89AB-CDEF-0123-456789ABCDEF",
			[]uefi.DepExOp{
				{OpCode: "PUSH", GUID: guid.MustParse("01234567-89AB-CDEF-0123-456789ABCDEF")},
				{OpCode: "END"}}, ""},
		{"pushtwo", "01234567-89AB-CDEF-0123-456789ABCDEF 01234567-89AB-CDEF-0123-456789ABCDEF",
			[]uefi.DepExOp{
				{OpCode: "PUSH", GUID: guid.MustParse("01234567-89AB-CDEF-0123-456789ABCDEF")},
				{OpCode: "PUSH", GUID: guid.MustParse("01234567-89AB-CDEF-0123-456789ABCDEF")},
				{OpCode: "AND"},
				{OpCode: "END"}}, ""},
		{"badGUID", "ABC", nil, "guid string not correct, need string of the format \n01234567-89AB-CDEF-0123-456789ABCDEF" +
			"\n, got \nABC"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outputs, err := createDepExes(test.input)
			if err = compareErrors(test.msg, err); err != nil {
				t.Fatal(err)
			}
			if err = compareOps(test.ops, outputs); err != nil {
				t.Fatal(err)
			}
		})
	}
}
