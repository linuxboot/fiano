package uefi

import (
	"encoding/json"
	"testing"
)

func TestUnmarshalTypedFirmware(t *testing.T) {
	inFirmware := MakeTyped(&Section{Name: "CHARLIE"})

	j, err := json.Marshal(inFirmware)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(j))

	var outFirmware TypedFirmware
	if err := json.Unmarshal(j, &outFirmware); err != nil {
		t.Fatal(err)
	}

	if outFirmware.Type != "*uefi.Section" {
		t.Errorf("got %q, expected *uefi.Section", outFirmware.Type)
	}
	outSection, ok := outFirmware.Value.(*Section)
	if !ok {
		t.Fatalf("got %T; expected *uefi.Section", outFirmware.Value)
	}
	if outSection.Name != "CHARLIE" {
		t.Errorf("got %q, expected CHARLIE", outSection.Name)
	}
}
