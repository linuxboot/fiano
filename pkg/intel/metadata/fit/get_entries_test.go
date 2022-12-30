// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"bytes"
	"compress/bzip2"
	"encoding/base64"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	fitHeadersSampleBZ2, _ = base64.StdEncoding.DecodeString(
		"QlpoOTFBWSZTWeqFfFEBARl/z/6cAAhAEAJAISIUAMAAYADAABBMUgACAI4AAAiwANiQkhUepkNBk0A0Gj0nqGMmmQMmhkGRpgRgVJRHqBPUGmBPQQB6mu/KQvlYVFwVWSqIERBhUJJEkSR53rKJMcLkAQB4VEmzyuIBAGNSSaLY2elZ4gEAapJc7BvQ6GAOz3zzwaWQh1wYvXevCRHSI64eYVYAyTeHJJpz9TxxkkkkkgAA+ewChlSjX5WsDQH+LuSKcKEh1Qr4og==")
)

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}

func TestGetEntries(t *testing.T) {
	firmwareBytes, err := io.ReadAll(bzip2.NewReader(bytes.NewReader(fitHeadersSampleBZ2)))
	panicIfError(err)

	entries, err := GetEntries(firmwareBytes)
	assert.NoError(t, err)

	assert.Equal(t, 27, len(entries))
}

func TestGetEntriesInvalidAddr(t *testing.T) {
	sampleEntries := getSampleEntries(t)
	for _, entry := range sampleEntries[1:] {
		entry.GetEntryBase().Headers.Address = 2<<32 + 1 // overflow
		entry.GetEntryBase().DataSegmentBytes = nil
	}

	dummyImage := make([]byte, 1024)
	err := sampleEntries.Inject(dummyImage, 512)
	require.NoError(t, err)

	// There should be no panic, and the errors should be inside entry headers.
	entries, err := GetEntries(dummyImage)
	require.NoError(t, err)
	for _, entry := range entries[1:] {
		switch entry := entry.(type) {
		case *EntrySkip:
			continue
		default:
			require.Contains(t, fmt.Sprintf("%v", entry.GetEntryBase().HeadersErrors), "index")
		}
	}
}

// BenchmarkGetEntries-8             520621              2357 ns/op            2944 B/op         59 allocs/op
func BenchmarkGetEntries(b *testing.B) {
	firmwareBytes, err := io.ReadAll(bzip2.NewReader(bytes.NewReader(fitHeadersSampleBZ2)))
	panicIfError(err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetEntries(firmwareBytes)
	}
}
