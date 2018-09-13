// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"testing"
)

func TestFind(t *testing.T) {
	f := parseImage(t)
	results := find(t, f, testGUID)

	// We expect one match
	if len(results) != 1 {
		t.Fatalf("got %d matches; expected 1", len(results))
	}
}
