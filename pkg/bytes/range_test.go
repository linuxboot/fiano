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

func TestRangeExclude(t *testing.T) {
	require.Equal(t,
		Ranges{
			Range{
				Offset: 0,
				Length: 1,
			},
			Range{
				Offset: 2,
				Length: 3,
			},
			Range{
				Offset: 6,
				Length: 4,
			},
		},
		Range{
			Offset: 0,
			Length: 10,
		}.Exclude(
			Range{
				Offset: 1,
				Length: 1,
			},
			Range{
				Offset: 5,
				Length: 1,
			},
		),
	)

	require.Equal(t,
		Ranges{
			Range{
				Offset: 1,
				Length: 9,
			},
		},
		Range{
			Offset: 0,
			Length: 10,
		}.Exclude(
			Range{
				Offset: 0,
				Length: 1,
			},
		),
	)

	require.Equal(t,
		Ranges{
			Range{
				Offset: 0,
				Length: 9,
			},
		},
		Range{
			Offset: 0,
			Length: 10,
		}.Exclude(
			Range{
				Offset: 9,
				Length: 1,
			},
		),
	)

	require.Equal(t,
		Ranges{
			Range{
				Offset: 11,
				Length: 9,
			},
		},
		Range{
			Offset: 10,
			Length: 10,
		}.Exclude(
			Range{
				Offset: 9,
				Length: 2,
			},
		),
	)

	require.Equal(t,
		Ranges{
			Range{
				Offset: 0,
				Length: 9,
			},
		},
		Range{
			Offset: 0,
			Length: 10,
		}.Exclude(
			Range{
				Offset: 9,
				Length: 2,
			},
		),
	)

	require.Equal(t,
		Ranges{
			Range{
				Offset: 0,
				Length: 10,
			},
		},
		Range{
			Offset: 0,
			Length: 10,
		}.Exclude(),
	)

	require.Equal(t,
		Ranges{
			Range{
				Offset: 10,
				Length: 10,
			},
		},
		Range{
			Offset: 10,
			Length: 10,
		}.Exclude(
			Range{
				Offset: 0,
				Length: 10,
			},
		),
	)

	require.Equal(t,
		Ranges{
			Range{
				Offset: 0,
				Length: 10,
			},
		},
		Range{
			Offset: 0,
			Length: 10,
		}.Exclude(
			Range{
				Offset: 10,
				Length: 10,
			},
		),
	)

	require.Equal(t,
		Ranges(nil),
		Range{
			Offset: 0,
			Length: 10,
		}.Exclude(
			Range{
				Offset: 0,
				Length: 10,
			},
		),
	)

	require.Equal(t,
		Ranges(nil),
		Range{
			Offset: 10,
			Length: 10,
		}.Exclude(
			Range{
				Offset: 0,
				Length: 30,
			},
		),
	)
}
