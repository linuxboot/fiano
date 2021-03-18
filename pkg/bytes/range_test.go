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
}
