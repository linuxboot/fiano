// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func randBytes(size uint) []byte {
	b := make([]byte, int(size))
	_, _ = rand.Read(b)
	return b
}

func TestEntrySACM_ParseData(t *testing.T) {
	sizeOffset := EntrySACMDataCommon{}.SizeBinaryOffset()
	sizeEndOffset := sizeOffset + uint(binary.Size(EntrySACMDataCommon{}.Size))

	versionOffset := EntrySACMDataCommon{}.HeaderVersionBinaryOffset()
	versionEndOffset := versionOffset + uint(binary.Size(EntrySACMDataCommon{}.HeaderVersion))

	keySizeOffset := EntrySACMDataCommon{}.KeySizeBinaryOffset()
	keySizeEndOffset := keySizeOffset + uint(binary.Size(EntrySACMDataCommon{}.KeySize))

	entry := EntrySACM{
		EntryBase: EntryBase{
			DataSegmentBytes: randBytes(65536),
			HeadersErrors:    nil,
		},
	}

	testPositive := func(t *testing.T, headersSize int) {
		data, err := entry.ParseData()
		require.NoError(t, err)

		_ = data.GetRSAPubKey()
		require.Zero(t, len(data.UserArea))
		require.Zero(t, len(entry.DataSegmentBytes)-headersSize)
		require.NotZero(t, data.GetKeySize())

		var buf bytes.Buffer
		_, err = data.WriteTo(&buf)
		require.NoError(t, err)

		dataCopy, err := ParseSACMData(&buf)
		require.NoError(t, err)

		require.Equal(t, data, dataCopy)
	}

	t.Run("SACMv0", func(t *testing.T) {
		binary.LittleEndian.PutUint32(entry.DataSegmentBytes[versionOffset:versionEndOffset], uint32(ACHeaderVersion0))
		binary.LittleEndian.PutUint32(entry.DataSegmentBytes[sizeOffset:sizeEndOffset], uint32(entrySACMData0Size)>>2)
		dataSize, err := EntrySACMParseSize(entry.DataSegmentBytes[:65536])
		require.NoError(t, err)
		entry.DataSegmentBytes = entry.DataSegmentBytes[:dataSize]
		t.Run("positive", func(t *testing.T) {
			binary.LittleEndian.PutUint32(entry.DataSegmentBytes[keySizeOffset:keySizeEndOffset], 256>>2)
			testPositive(t, int(entrySACMData0Size))
		})
	})

	t.Run("SACMv3", func(t *testing.T) {
		binary.LittleEndian.PutUint32(entry.DataSegmentBytes[versionOffset:versionEndOffset], uint32(ACHeaderVersion3))
		binary.LittleEndian.PutUint32(entry.DataSegmentBytes[sizeOffset:sizeEndOffset], uint32(entrySACMData3Size)>>2)
		dataSize, err := EntrySACMParseSize(entry.DataSegmentBytes[:65536])
		require.NoError(t, err)
		entry.DataSegmentBytes = entry.DataSegmentBytes[:dataSize]
		t.Run("positive", func(t *testing.T) {
			binary.LittleEndian.PutUint32(entry.DataSegmentBytes[keySizeOffset:keySizeEndOffset], 384>>2)
			testPositive(t, int(entrySACMData3Size))
		})
		t.Run("negative_keySize", func(t *testing.T) {
			binary.LittleEndian.PutUint32(entry.DataSegmentBytes[keySizeOffset:keySizeEndOffset], 256>>2)

			_, err := entry.ParseData()
			require.Error(t, err)
		})
	})

	t.Run("SACM_invalidVersion", func(t *testing.T) {
		binary.LittleEndian.PutUint32(entry.DataSegmentBytes[versionOffset:versionEndOffset], 0x12345678)
		binary.LittleEndian.PutUint32(entry.DataSegmentBytes[sizeOffset:sizeEndOffset], uint32(entrySACMData0Size)>>2)
		dataSize, err := EntrySACMParseSize(entry.DataSegmentBytes[:65536])
		require.NoError(t, err)
		entry.DataSegmentBytes = entry.DataSegmentBytes[:dataSize]

		_, err = entry.ParseData()
		require.Error(t, err)
	})
}
