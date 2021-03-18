package fit

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func randBytes(size uint) []byte {
	rand.Seed(0)
	b := make([]byte, int(size))
	rand.Read(b)
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
			Headers:       nil,
			DataOffset:    nil,
			DataBytes:     randBytes(65536),
			HeadersErrors: nil,
		},
	}

	t.Run("SACMv0", func(t *testing.T) {
		binary.LittleEndian.PutUint32(entry.DataBytes[versionOffset:versionEndOffset], uint32(ACHeaderVersion0))
		binary.LittleEndian.PutUint32(entry.DataBytes[sizeOffset:sizeEndOffset], uint32(entrySACMData0Size)>>2)
		dataSize, err := EntrySACMParseSize(entry.DataBytes[:65536])
		require.NoError(t, err)
		entry.DataBytes = entry.DataBytes[:dataSize]
		t.Run("positive", func(t *testing.T) {
			binary.LittleEndian.PutUint32(entry.DataBytes[keySizeOffset:keySizeEndOffset], 256>>2)

			data, err := entry.ParseData()
			require.NoError(t, err)

			_ = data.GetRSAPubKey()
			require.Zero(t, len(data.UserArea))
			require.Zero(t, len(entry.DataBytes)-int(entrySACMData0Size))
		})
	})

	t.Run("SACMv3", func(t *testing.T) {
		binary.LittleEndian.PutUint32(entry.DataBytes[versionOffset:versionEndOffset], uint32(ACHeaderVersion3))
		binary.LittleEndian.PutUint32(entry.DataBytes[sizeOffset:sizeEndOffset], uint32(entrySACMData3Size)>>2)
		dataSize, err := EntrySACMParseSize(entry.DataBytes[:65536])
		require.NoError(t, err)
		entry.DataBytes = entry.DataBytes[:dataSize]
		t.Run("positive", func(t *testing.T) {
			binary.LittleEndian.PutUint32(entry.DataBytes[keySizeOffset:keySizeEndOffset], 384>>2)

			data, err := entry.ParseData()
			require.NoError(t, err)

			_ = data.GetRSAPubKey()
			require.Zero(t, len(data.UserArea))
			require.Zero(t, len(entry.DataBytes)-int(entrySACMData3Size))
		})
		t.Run("negative_keySize", func(t *testing.T) {
			binary.LittleEndian.PutUint32(entry.DataBytes[keySizeOffset:keySizeEndOffset], 256>>2)

			_, err := entry.ParseData()
			require.Error(t, err)
		})
	})

	t.Run("SACM_invalidVersion", func(t *testing.T) {
		binary.LittleEndian.PutUint32(entry.DataBytes[versionOffset:versionEndOffset], 0x12345678)
		binary.LittleEndian.PutUint32(entry.DataBytes[sizeOffset:sizeEndOffset], uint32(entrySACMData0Size)>>2)
		dataSize, err := EntrySACMParseSize(entry.DataBytes[:65536])
		require.NoError(t, err)
		entry.DataBytes = entry.DataBytes[:dataSize]

		_, err = entry.ParseData()
		require.Error(t, err)
	})
}
