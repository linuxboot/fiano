package visitors

import (
	"io/ioutil"
	"regexp"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// ReplacePE32 replaces PE32 sections with NewPE32 for all files matching Predicate.
type ReplacePE32 struct {
	// Input
	Predicate func(f *uefi.File, name string) bool
	NewPE32   []byte

	// Output
	Matches []*uefi.File
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *ReplacePE32) Run(f uefi.Firmware) error {
	// First run "find" to generate a list of matches to replace.
	find := Find{
		Predicate: v.Predicate,
	}
	if err := find.Run(f); err != nil {
		return err
	}

	// Use this list of matches for replacing sections.
	v.Matches = find.Matches
	for _, m := range v.Matches {
		if err := m.Apply(v); err != nil {
			return err
		}
	}
	return nil
}

// Visit applies the Extract visitor to any Firmware type.
func (v *ReplacePE32) Visit(f uefi.Firmware) error {
	switch f := f.(type) {

	case *uefi.File:
		return f.ApplyChildren(v)

	case *uefi.Section:
		if f.Header.Type == uefi.SectionTypePE32 {
			f.SetBuf(v.NewPE32)
			f.Encapsulated = nil // Should already be empty
			f.GenSecHeader()
		}
		return f.ApplyChildren(v)

	default:
		// Must be applied to a File to have any effect.
		return nil
	}
}

func init() {
	RegisterCLI("replace_pe32", 2, func(args []string) (uefi.Visitor, error) {
		searchRE, err := regexp.Compile(args[0])
		if err != nil {
			return nil, err
		}

		filename := args[1]
		newPE32, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}

		// Find all the matching files and replace their inner PE32s.
		return &ReplacePE32{
			Predicate: func(f *uefi.File, name string) bool {
				return searchRE.MatchString(name) || searchRE.MatchString(f.Header.UUID.String())
			},
			NewPE32: newPE32,
		}, nil
	})
}
