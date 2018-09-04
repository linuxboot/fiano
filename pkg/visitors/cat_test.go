// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/linuxboot/fiano/pkg/uefi"
	"github.com/linuxboot/fiano/pkg/uuid"
)

var (
	catGUID = uuid.MustParse("1B45CC0A-156A-428A-AF62-49864DA0E6E6")
	catdat  = []byte{79, 218, 58, 155, 86, 174, 36, 76, 141, 234, 240, 59, 117, 88, 174, 80}
)

func TestCat(t *testing.T) {
	f := parseImage(t)

	// Apply the visitor.
	var b bytes.Buffer
	cat := &Cat{
		Predicate: func(f *uefi.File, name string) bool {
			m := f.Header.UUID == *catGUID
			t.Logf("Check file UUID %v against %v: %v", f.Header.UUID.String(), *catGUID, m)
			return m
		},
		Writer: &b,
	}
	if err := cat.Run(f); err != nil {
		t.Fatal(err)
	}

	// We expect one match.
	if len(cat.Matches) != 1 {
		t.Fatalf("got %d matches; expected 1", len(cat.Matches))
	}

	if !reflect.DeepEqual(b.Bytes(), catdat) {
		t.Errorf("bytes.Buffer: want %v; got %v", catdat, b.Bytes())
	}
}
