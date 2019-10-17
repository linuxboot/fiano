// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

import (
	"reflect"
	"testing"
)

func TestMEName_MarshalText(t *testing.T) {
	var tests = []struct {
		name string
		me   MEName
	}{
		{"NAME", MEName{'N', 'A', 'M', 'E'}},
		{"NAM", MEName{'N', 'A', 'M', 0}},
		{"NA", MEName{'N', 'A', 0, 0}},
		{"N", MEName{'N', 0, 0, 0}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b, err := test.me.MarshalText()
			if err != nil {
				t.Errorf("Unexpected error %v", err)
			}
			if string(b) != test.name {
				t.Errorf("error got %q want %q", b, test.name)
			}
		})
	}
}

func TestMEName_UnmarshalText(t *testing.T) {
	var tests = []struct {
		name string
		me   MEName
		msg  string
	}{
		{"NAME", MEName{'N', 'A', 'M', 'E'}, ""},
		{"NAM", MEName{'N', 'A', 'M', 0}, ""},
		{"NA", MEName{'N', 'A', 0, 0}, ""},
		{"N", MEName{'N', 0, 0, 0}, ""},
		{"NAME1", MEName{'N', 'A', 'M', 'E'}, "Can’t unmarshal \"NAME1\" to MEName, 5 > 4"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			me := MEName{'F', 'U', 'L', 'L'}
			err := me.UnmarshalText([]byte(test.name))
			if err == nil && test.msg != "" {
				t.Errorf("Error was not returned, expected %v", test.msg)
			} else if err != nil && err.Error() != test.msg {
				t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
			} else if !reflect.DeepEqual(me, test.me) {
				t.Errorf("error got %q want %q", me, test.me)
			}

		})
	}
}
