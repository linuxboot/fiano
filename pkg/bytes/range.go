package bytes

import (
	"fmt"
	"sort"
	"strings"
)

// Range defines is a generic bytes range headers.
type Range struct {
	Offset uint64
	Length uint64
}

func (r Range) String() string {
	return fmt.Sprintf(`{"Offset":"0x%x", "Length":"0x%x"}`, r.Offset, r.Length)
}

// Intersect returns True if ranges "r" and "cmp" has at least
// one byte with the same offset.
func (r Range) Intersect(cmp Range) bool {
	if r.Length == 0 || cmp.Length == 0 {
		return false
	}

	startIdx0 := r.Offset
	startIdx1 := cmp.Offset
	endIdx0 := startIdx0 + r.Length
	endIdx1 := startIdx1 + cmp.Length

	if endIdx0 <= startIdx1 {
		return false
	}
	if startIdx0 >= endIdx1 {
		return false
	}

	return true
}

// Ranges is a helper to manipulate multiple `Range`-s at once
type Ranges []Range

func (s Ranges) String() string {
	r := make([]string, 0, len(s))
	for _, oneRange := range s {
		r = append(r, oneRange.String())
	}
	return `[` + strings.Join(r, `, `) + `]`
}

// Sort sorts the slice by field Offset
func (s Ranges) Sort() {
	sort.Slice(s, func(i, j int) bool {
		return s[i].Offset < s[j].Offset
	})
}

// MergeRanges just merges ranges which has distance less or equal to
// mergeDistance.
//
// Warning: should be called only on sorted ranges!
func MergeRanges(in Ranges, mergeDistance uint64) Ranges {
	if len(in) < 2 {
		return in
	}

	var result Ranges
	entry := in[0]
	for _, nextEntry := range in[1:] {
		// merge "nextEntry" to "entry" if the distance is lower or equal to
		// mergeDistance.

		if entry.Offset+entry.Length+mergeDistance >= nextEntry.Offset {
			entry.Length = (nextEntry.Offset - entry.Offset) + nextEntry.Length
			continue
		}

		result = append(result, entry)
		entry = nextEntry
	}
	result = append(result, entry)

	return result
}

// SortAndMerge sorts the slice (by field Offset) and the merges ranges
// which could be merged.
func (s *Ranges) SortAndMerge() {
	// See also TestDiffEntriesSortAndMerge

	if len(*s) < 2 {
		return
	}
	s.Sort()

	*s = MergeRanges(*s, 0)
}

// Compile returns the bytes from `b` which are referenced by `Range`-s `s`.
func (s Ranges) Compile(b []byte) []byte {
	var result []byte
	for _, r := range s {
		result = append(result, b[r.Offset:r.Offset+r.Length]...)
	}
	return result
}

// IsIn returns if the index is covered by this ranges
func (s Ranges) IsIn(index uint64) bool {
	for _, r := range s {
		startIdx := r.Offset
		endIdx := r.Offset + r.Length
		// `startIdx` is inclusive, while `endIdx` is exclusive.
		// The same as usual slice indices works:
		//
		//     slice[startIdx:endIdx]

		if startIdx <= index && index < endIdx {
			return true
		}
	}
	return false
}
