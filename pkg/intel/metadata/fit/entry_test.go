// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntkey"
	"github.com/stretchr/testify/require"
	"github.com/xaionaro-go/bytesextra"
)

func TestRehashEntry(t *testing.T) {
	for _, entryType := range AllEntryTypes() {
		switch entryType {
		case EntryTypeDiagnosticACModuleEntry,
			EntryTypeTPMPolicyRecord:
			// not supported yet
			continue
		}

		entry := entryType.newEntry()
		*entry.GetEntryBase() = EntryBase{
			DataSegmentBytes: make([]byte, 0x20),
			HeadersErrors:    nil,
		}
		func() {
			defer func() {
				_r := recover()
				if strings.Contains(fmt.Sprint(_r), "should not be used for an entry type") {
					// It does not make sense to call method GetHeaders().DataSize() on
					// some EntryType-s, see (*EntryHeaders).DataSize()
					//
					// This is because data size for some entries is not stored in the headers.
					return
				}
				require.Nil(t, _r)
			}()

			// Validating there is no errors
			err := EntryRecalculateHeaders(entry)
			if err != nil {
				// Not all entry types are fully implemented, see RehashEntry()
				t.Errorf("%v", err)
			}

			// Validating that DataSize() calculates sizes consistently with RehashEntry()
			if entryType != EntryTypeStartupACModuleEntry {
				dataSize, err := EntryDataSegmentSize(entry, nil)
				require.NoError(t, err)
				if dataSize != 0 && dataSize != uint64(len(entry.GetEntryBase().DataSegmentBytes)) {
					t.Errorf("wrong DataSize 0x%X for type %s", dataSize, entryType)
				}
			}
		}()
	}
}

func getSampleEntries(t *testing.T) Entries {
	var entries Entries
	headerEntry := &EntryFITHeaderEntry{}
	skipEntry := &EntrySkip{}

	kmEntry := &EntryKeyManifestRecord{}
	{
		km := cbntkey.NewManifest()
		var buf bytes.Buffer
		_, err := km.WriteTo(&buf)
		require.NoError(t, err)
		kmEntry.DataSegmentBytes = buf.Bytes()
	}
	kmEntry.Headers.Address.SetOffset(256, 1024)

	entries = append(entries, headerEntry)
	entries = append(entries, skipEntry)
	entries = append(entries, kmEntry)
	err := entries.RecalculateHeaders()
	require.NoError(t, err)
	return entries
}

func TestEntriesInject(t *testing.T) {
	testResult := func(t *testing.T, b []byte) {
		entries := getSampleEntries(t)

		parsedEntries, err := GetEntries(b)
		require.NoError(t, err)
		require.Equal(t, len(entries), len(parsedEntries))
		for idx, parsedEntry := range parsedEntries {
			require.Equal(t, entries[idx].GetEntryBase().DataSegmentBytes, parsedEntry.GetEntryBase().DataSegmentBytes)
		}
	}

	t.Run("Inject", func(t *testing.T) {
		entries := getSampleEntries(t)
		b := make([]byte, 1024)
		err := entries.Inject(b, 512)
		require.NoError(t, err)

		testResult(t, b)
	})

	t.Run("InjectTo", func(t *testing.T) {
		entries := getSampleEntries(t)
		b := make([]byte, 1024)
		err := entries.InjectTo(bytesextra.NewReadWriteSeeker(b), 512)
		require.NoError(t, err)

		testResult(t, b)
	})
}
