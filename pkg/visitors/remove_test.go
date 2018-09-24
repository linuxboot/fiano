// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"testing"
)

func TestRemove(t *testing.T) {
	f := parseImage(t)

	// Apply the visitor.
	remove := &Remove{
		Predicate: FindFileGUIDPredicate(*testGUID),
	}
	if err := remove.Run(f); err != nil {
		t.Fatal(err)
	}

	// We expect one match.
	if len(remove.Matches) != 1 {
		t.Fatalf("got %d matches; expected 1", len(remove.Matches))
	}

	// We expect no match.
	results := find(t, f, testGUID)
	if len(results) != 0 {
		t.Fatalf("got %d matches; expected 0", len(results))
	}
}
