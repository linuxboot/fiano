// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"testing"
)

func TestRemoveNoPad(t *testing.T) {
	f := parseImage(t)

	count := &Count{}
	if err := count.Run(f); err != nil {
		t.Fatal(err)
	}
	padCount := count.FileTypeCount["EFI_FV_FILETYPE_FFS_PAD"]
	// Apply the visitor.
	remove := &Remove{
		Predicate: FindFileGUIDPredicate(*testGUID),
		Pad:       false,
	}
	if err := remove.Run(f); err != nil {
		t.Fatal(err)
	}

	// We expect one match.
	if len(remove.Matches) != 1 {
		t.Fatalf("got %d matches; expected 1", len(remove.Matches))
	}

	// We expect no match.
	results := find(t, f, testGUID)
	if len(results) != 0 {
		t.Errorf("got %d matches; expected 0", len(results))
	}
	// We expect the same number of pad files
	if err := count.Run(f); err != nil {
		t.Fatal(err)
	}
	if newPadCount := count.FileTypeCount["EFI_FV_FILETYPE_FFS_PAD"]; padCount != newPadCount {
		t.Errorf("differing number of pad files: originally had %v, after removal got %v",
			padCount, newPadCount)
	}
}

func TestRemovePad(t *testing.T) {
	f := parseImage(t)

	count := &Count{}
	if err := count.Run(f); err != nil {
		t.Fatal(err)
	}
	padCount := count.FileTypeCount["EFI_FV_FILETYPE_FFS_PAD"]
	// Apply the visitor.
	remove := &Remove{
		Predicate: FindFileGUIDPredicate(*testGUID),
		Pad:       true,
	}
	if err := remove.Run(f); err != nil {
		t.Fatal(err)
	}

	// We expect one match.
	if len(remove.Matches) != 1 {
		t.Fatalf("got %d matches; expected 1", len(remove.Matches))
	}

	// We expect no match.
	results := find(t, f, testGUID)
	if len(results) != 0 {
		t.Fatalf("got %d matches; expected 0", len(results))
	}
	// We expect one more pad file
	if err := count.Run(f); err != nil {
		t.Fatal(err)
	}
	if newPadCount := count.FileTypeCount["EFI_FV_FILETYPE_FFS_PAD"]; padCount+1 != newPadCount {
		t.Errorf("differing number of pad files: expected %v, got %v",
			padCount+1, newPadCount)
	}
}

func TestRemoveExcept(t *testing.T) {
	f := parseImage(t)

	pred, err := FindFilePredicate(dxeCoreGUID.String())
	if err != nil {
		t.Fatal(err)
	}
	remove := &Remove{
		Predicate:  pred,
		RemoveDxes: true,
	}
	if err := remove.Run(f); err != nil {
		t.Fatal(err)
	}

	// We expect no more dxe drivers since we only kept the core.
	count := &Count{}
	if err := count.Run(f); err != nil {
		t.Fatal(err)
	}
	dxeCount := count.FileTypeCount["EFI_FV_FILETYPE_DRIVER"]
	coreCount := count.FileTypeCount["EFI_FV_FILETYPE_DXE_CORE"]
	if dxeCount != 0 {
		t.Errorf("expected no more drivers, got %v", dxeCount)
	}
	if coreCount != 1 {
		t.Errorf("expected one dxecore remaining, got %v", coreCount)
	}

}
