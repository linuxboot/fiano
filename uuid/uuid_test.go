package uuid

import (
	"fmt"
	"testing"
)

var (
	// UUID examples
	exampleUUID UUID = [16]byte{0x67, 0x45, 0x23, 0x01, 0xAB, 0x89, 0xEF, 0xCD,
		0x23, 0x01, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	// UUID string examples
	exampleUUIDString   = "01234567-89AB-CDEF-0123-456789ABCDEF"
	shortUUIDString     = "0123456789ABCDEF0123456789ABCDEF"
	badUUIDStringLength = "01234567"
	badHex              = "GHGHGHGHGHGHGH"
)

func TestParse(t *testing.T) {
	var tests = []struct {
		s   string
		u   *UUID
		msg string
	}{
		{exampleUUIDString, &exampleUUID, ""},
		{shortUUIDString, &exampleUUID, ""},
		{badUUIDStringLength, nil, fmt.Sprintf("uuid string has incorrect length, need string of the format \n%v\n, got \n%v",
			UExample, badUUIDStringLength)},
		{badHex, nil, fmt.Sprintf("uuid string not correct, need string of the format \n%v\n, got \n%v",
			UExample, badHex)},
	}
	for _, test := range tests {
		u, err := Parse(test.s)
		if u == nil {
			if test.u != nil {
				t.Errorf("UUID was expected: %v, got nil", test.u)
			}
			if err == nil {
				t.Errorf("Error was not returned, expected %v", test.msg)
			} else if err.Error() != test.msg {
				t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
			}
		} else if *u != *test.u {
			t.Errorf("UUID was parsed incorrectly, expected %v\n, got %v\n, string was %v", test.u, u, test.s)
		}
	}
}
