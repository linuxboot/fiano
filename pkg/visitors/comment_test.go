// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"testing"
)

func TestComment(t *testing.T) {
	f := parseImage(t)
	results := comment(t, f)

	if len(results) != 0 {
		t.Fatalf("got %d matches; expected 0", len(results))
	}
}
