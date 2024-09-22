// Copyright 2024 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCBFS(t *testing.T) {
	t.Run("usage error", func(t *testing.T) {
		err := run(io.Discard, false, []string{"list"})
		if !errors.Is(err, errUsage) {
			t.Errorf("expected %v, got nil", errUsage)
		}
	})

	t.Run("unknown command", func(t *testing.T) {
		err := run(io.Discard, false, []string{"testdata/coreboot.rom", "unknown"})
		if !errors.Is(err, errUsage) {
			t.Errorf("expected %v, got nil", errUsage)
		}
	})

	t.Run("list command", func(t *testing.T) {
		stdout := &bytes.Buffer{}
		err := run(stdout, false, []string{"testdata/coreboot.rom", "list"})
		if err != nil {
			t.Fatalf("expected nil got %v", err)
		}

		if !strings.Contains(stdout.String(), "fallback/ramstage") {
			t.Errorf("output doesn't contain `fallback/ramstage`, %s", stdout.String())
		}
	})

	t.Run("list json", func(t *testing.T) {
		stdout := &bytes.Buffer{}
		err := run(stdout, false, []string{"testdata/coreboot.rom", "json"})
		if err != nil {
			t.Fatalf("expected nil got %v", err)
		}

		if !strings.Contains(stdout.String(), "fallback/ramstage") {
			t.Errorf("output doesn't contain `fallback/ramstage`, %s", stdout.String())
		}

		j := make(map[string]any)
		err = json.Unmarshal(stdout.Bytes(), &j)
		if err != nil {
			t.Errorf("expected json output, got unmarshal error: %v", err)
		}
	})

	t.Run("extract missing dir", func(t *testing.T) {
		err := run(io.Discard, false, []string{"testdata/coreboot.rom", "extract"})
		if !errors.Is(err, errMissingDirectory) {
			t.Errorf("expected %v, got nil", errMissingDirectory)
		}
	})

	t.Run("extract", func(t *testing.T) {
		dir := t.TempDir()
		// save local path
		romPath, err := filepath.Abs("testdata/coreboot.rom")
		if err != nil {
			t.Fatal(err)
		}

		err = os.Chdir(dir)
		if err != nil {
			t.Fatal(err)
		}

		err = run(io.Discard, false, []string{romPath, "extract", "firmware"})
		if err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})
}
