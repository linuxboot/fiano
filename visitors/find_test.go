package visitors

import (
	"io/ioutil"
	"testing"

	"github.com/linuxboot/fiano/uefi"
	"github.com/linuxboot/fiano/uuid"
)

func TestFind(t *testing.T) {
	// Parse image.
	image, err := ioutil.ReadFile("../integration/roms/OVMF.rom")
	if err != nil {
		t.Fatal(err)
	}
	parsedRoot, err := uefi.Parse(image)
	if err != nil {
		t.Fatal(err)
	}

	// Apply the visitor
	searchUUID := uuid.MustParse("DF1CCEF6-F301-4A63-9661-FC6030DCC880")
	v := &Find{
		Predicate: func(f *uefi.File, name string) bool {
			return f.Header.UUID == *searchUUID
		},
	}
	if err := parsedRoot.Apply(v); err != nil {
		t.Fatal(err)
	}

	// We expect one match
	if len(v.Matches) != 1 {
		t.Fatalf("got %d matches; expected 1", len(v.Matches))
	}
}
