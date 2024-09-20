// Copyright 2020 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// SPDX-License-Identifier: BSD-3-Clause
//

package uefi

import (
	"archive/tar"
	"fmt"
	"io"
	"log"
	"os"
	fp "path/filepath"
	"testing"

	"github.com/ulikunitz/xz"
)

// no-op writer to minimize logging overhead
type nopWriter struct{}

func (n *nopWriter) Write(_ []byte) (int, error) { return 0, nil }

// Tests using input from fuzzing runs. Ignores any errors, just checks that the
// inputs do not cause crashes.
//
// To update the input zip after a fuzzing run:
// cd fuzz/corpus
// zip ../../testdata/fuzz_in.zip *
//
// Similarly, the zip can be extracted to use as input corpus. See fuzz.go for
// go-fuzz instructions.
func TestFuzzInputs(t *testing.T) {
	// if testing.CoverMode() != "" {
	// NOTE - since this test doesn't validate the outputs, coverage from
	// it is very low value, essentially inflating the coverage numbers.
	// t.Skip("this test will inflate coverage")
	// }

	// not available in go < 1.13
	// //restore log behavior at end
	// logOut := log.Writer()
	// defer log.SetOutput(logOut)

	//no logging output for this test, to increase speed
	log.SetOutput(&nopWriter{})
	log.SetFlags(0)

	txz, err := os.Open("testdata/fuzz_in.txz")
	if err != nil {
		t.Fatal(err)
	}
	defer txz.Close()
	x, err := xz.NewReader(txz)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(x)
	for i := 0; ; i++ {
		zf, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Error(err)
			continue
		}
		n := fp.Base(zf.Name)
		if len(n) > 10 {
			n = n[:10]
		} else {
			t.Logf("short: %s", n)
		}
		name := fmt.Sprintf("%03d_%s", i, n)
		t.Run(name, func(t *testing.T) {
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Error(err)
			}
			//reset polarity before each run, some fuzz files change it
			Attributes = ROMAttributes{ErasePolarity: poisonedPolarity}
			//ignore any errors - just catch crashes
			_, _ = Parse(data)
		})
	}
}
