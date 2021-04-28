package bytes

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRangesSortAndMerge(t *testing.T) {
	t.Run("nothing_to_merge", func(t *testing.T) {
		entries := Ranges{{
			Offset: 2,
			Length: 1,
		}, {
			Offset: 0,
			Length: 1,
		}}
		entries.SortAndMerge()
		require.Equal(t, Ranges{{
			Offset: 0,
			Length: 1,
		}, {
			Offset: 2,
			Length: 1,
		}}, entries)
	})
	t.Run("merge_overlapping", func(t *testing.T) {
		entries := Ranges{{
			Offset: 2,
			Length: 3,
		}, {
			Offset: 0,
			Length: 3,
		}}
		entries.SortAndMerge()
		require.Equal(t, Ranges{{
			Offset: 0,
			Length: 5,
		}}, entries)
	})
	t.Run("merge_no_distance", func(t *testing.T) {
		entries := Ranges{{
			Offset: 2,
			Length: 2,
		}, {
			Offset: 0,
			Length: 2,
		}}
		entries.SortAndMerge()
		require.Equal(t, Ranges{{
			Offset: 0,
			Length: 4,
		}}, entries)
	})
	t.Run("merge_next_range_inside_previous", func(t *testing.T) {
		entries := Ranges{
			{
				Offset: 0,
				Length: 0,
			},
			{
				Offset: 12320788,
				Length: 4,
			},
			{
				Offset: 12255584,
				Length: 32,
			},
			{
				Offset: 12582912,
				Length: 4194304,
			},
			{
				Offset: 15760208,
				Length: 67646,
			},
			{
				Offset: 1114112,
				Length: 11141120,
			},
			{
				Offset: 16777152,
				Length: 16,
			},
			{
				Offset: 12255232,
				Length: 432,
			},
		}
		entries.SortAndMerge()
		require.Equal(t, Ranges{
			{
				Offset: 0,
				Length: 0,
			},
			{
				Offset: 1114112,
				Length: 11141552,
			},
			{
				Offset: 12320788,
				Length: 4,
			},
			{
				Offset: 12582912,
				Length: 4194304,
			},
		}, entries)
	})
}
