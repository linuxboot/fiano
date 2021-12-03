// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bytes

import (
	"testing"
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
		assertEqualRanges(t, Ranges{{
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
		assertEqualRanges(t, Ranges{{
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
		assertEqualRanges(t, Ranges{{
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
		assertEqualRanges(t, Ranges{
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
	assertEqualRanges(t,
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

	assertEqualRanges(t,
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

	assertEqualRanges(t,
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

	assertEqualRanges(t,
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

	assertEqualRanges(t,
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

	assertEqualRanges(t,
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

	assertEqualRanges(t,
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

	assertEqualRanges(t,
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

	assertEqualRanges(t,
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

	assertEqualRanges(t,
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

func assertEqualRanges(t *testing.T, expected, actual Ranges) {
	if len(expected) != len(actual) {
		t.Errorf("Expected number of ranges: %d, got: %d", len(expected), len(actual))
	}
	if len(expected) == 0 {
		return
	}

	for i := 0; i < len(expected); i++ {
		expectedRange := expected[i]
		actualRange := actual[i]

		if expectedRange.Offset != actualRange.Offset || expectedRange.Length != actualRange.Length {
			t.Errorf("Range element %d is different, expected: [%d:%d], got: [%d:%d]",
				i,
				expectedRange.Offset,
				actualRange.Offset,
				expectedRange.Length,
				actualRange.Length,
			)
		}
	}
}
