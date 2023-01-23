// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"bytes"
	"os"
	"testing"
)

func TestDump(t *testing.T) {
	f := parseImage(t)

	b := bytes.Buffer{}
	// Apply the visitor.
	dump := &Dump{
		Predicate: FindFileGUIDPredicate(*testGUID),
		W:         &b,
	}
	if err := dump.Run(f); err != nil {
		t.Fatal(err)
	}

	// Read in expected file.
	file, err := os.ReadFile("../../integration/roms/testfile.ffs")
	if err != nil {
		t.Fatal(err)
	}
	// W should now contain the file.
	if !bytes.Equal(b.Bytes(), file) {
		// TODO: Should dump the file somewhere for comparison.
		t.Errorf("files are not equal! expected file is in integration/roms/testfile.ffs")
	}
}
