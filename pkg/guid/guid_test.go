// Copyright 2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package guid

import (
	"fmt"
	"testing"
)

var (
	// GUID examples
	exampleGUID GUID = [16]byte{0x67, 0x45, 0x23, 0x01, 0xAB, 0x89, 0xEF, 0xCD,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	// GUID string examples
	exampleGUIDString   = "01234567-89AB-CDEF-0123-456789ABCDEF"
	shortGUIDString     = "0123456789ABCDEF0123456789ABCDEF"
	badGUIDStringLength = "01234567"
	badHex              = "GHGHGHGHGHGHGH"

	// GUID JSON examples
	exampleJSON       = `{"GUID" : "` + exampleGUIDString + `"}`
	exampleJSONBadHex = `{"GUID" : "` + badHex + `"}`
	exampleJSONBadKey = `{"UU" : "` + exampleGUIDString + `"}`
)

func TestParse(t *testing.T) {
	var tests = []struct {
		s   string
		u   *GUID
		msg string
	}{
		{exampleGUIDString, &exampleGUID, ""},
		{shortGUIDString, &exampleGUID, ""},
		{badGUIDStringLength, nil, fmt.Sprintf("guid string has incorrect length, need string of the format \n%v\n, got \n%v",
			UExample, badGUIDStringLength)},
		{badHex, nil, fmt.Sprintf("guid string not correct, need string of the format \n%v\n, got \n%v",
			UExample, badHex)},
	}
	for _, test := range tests {
		u, err := Parse(test.s)
		if u == nil {
			if test.u != nil {
				t.Errorf("GUID was expected: %v, got nil", test.u)
			}
			if err == nil {
				t.Errorf("Error was not returned, expected %v", test.msg)
			} else if err.Error() != test.msg {
				t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
			}
		} else if *u != *test.u {
			t.Errorf("GUID was parsed incorrectly, expected %v\n, got %v\n, string was %v", test.u, u, test.s)
		}
	}
}

func TestMarshal(t *testing.T) {
	var tests = []struct {
		j string
		u *GUID
	}{
		{exampleJSON, &exampleGUID},
	}
	for _, test := range tests {
		j, err := test.u.MarshalJSON()
		if err != nil {
			t.Errorf("No error was expected, got %v", err)
		}
		if test.j != string(j) {
			t.Errorf("JSON strings are not equal. Expected:\n%v\ngot:\n%v", test.j, string(j))
		}
	}
}

func TestUnmarshal(t *testing.T) {
	var tests = []struct {
		j   string
		u   *GUID
		msg string
	}{
		{exampleJSON, &exampleGUID, ""},
		{exampleJSONBadHex, nil, fmt.Sprintf("guid string not correct, need string of the format \n%v\n, got \n%v",
			UExample, badHex)},
		{exampleJSONBadKey, nil, fmt.Sprintf("guid string has incorrect length, need string of the format \n%v\n, got \n%v",
			UExample, "")},
	}
	for _, test := range tests {
		var g GUID
		err := g.UnmarshalJSON([]byte(test.j))
		if test.msg == "" && err != nil {
			t.Errorf("No error was expected, got %v", err)
		}
		if test.msg != "" && err == nil {
			t.Errorf("Error was expected: %v, got nil", test.msg)
		}
		if err != nil && err.Error() != test.msg {
			t.Errorf("Got Error msg %v, was expecting %v", err.Error(), test.msg)
		}
		if test.u != nil && *test.u != g {
			t.Errorf("GUIDs are not equal. Expected:\n%v\ngot:\n%v", test.u, g)
		}
	}
}
