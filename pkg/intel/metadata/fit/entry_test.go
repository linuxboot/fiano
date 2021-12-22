package fit

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRehashEntry(t *testing.T) {
	for _, entryType := range AllEntryTypes() {
		entryBase := EntryBase{
			Headers:       &EntryHeaders{},
			DataOffset:    &[]uint64{1}[0],
			DataBytes:     make([]byte, 0x20),
			HeadersErrors: nil,
		}
		entry := entryType.NewEntry(entryBase)
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
			err := RehashEntry(entry)
			if err != nil && !strings.Contains(err.Error(), "not implemented, yet") {
				// Not all entry types are fully implemented, see RehashEntry()
				t.Errorf("%v", err)
			}

			// Validating that DataSize() calculates sizes consistently with RehashEntry()
			dataSize := entry.GetHeaders().DataSize()
			if dataSize != 0 && dataSize != uint32(len(entryBase.DataBytes)) {
				t.Errorf("wrong DataSize 0x%X for type %s", dataSize, entryType)
			}
		}()
	}
}

func TestEntriesInject(t *testing.T) {
	var entries Entries

	headerEntry := &EntryFITHeaderEntry{}
	skipEntry := &EntrySkip{}
	kmEntry := &EntryKeyManifestRecord{}
	entries = append(entries, headerEntry)
	entries = append(entries, skipEntry)
	entries = append(entries, kmEntry)

	t.Run("Inject", func(t *testing.T) {
		b := make([]byte, 1024)
		err := entries.Inject(b, 512)
		require.NoError(t, err)
		require.Equal(t, nil, b)
	})

	t.Run("InjectTo", func(t *testing.T) {
		b := make([]byte, 1024)
		err := entries.InjectTo(newWriteSeekerWrapper(b), 512)
		require.NoError(t, err)
		require.Equal(t, nil, b)
	})
}
