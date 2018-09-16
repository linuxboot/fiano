// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// Count counts the number of each firmware type.
type Count struct {
	// Optionally write result as JSON.
	W io.Writer `json:"-"`

	// Output
	FirmwareTypeCount map[string]int
	FileTypeCount     map[string]int
	SectionTypeCount  map[string]int
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Count) Run(f uefi.Firmware) error {
	v.FirmwareTypeCount = map[string]int{}
	v.FileTypeCount = map[string]int{}
	v.SectionTypeCount = map[string]int{}

	if err := f.Apply(v); err != nil {
		return err
	}

	if v.W != nil {
		b, err := json.MarshalIndent(v, "", "\t")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(v.W, string(b))
		return err
	}
	return nil
}

// Visit applies the Count visitor to any Firmware type.
func (v *Count) Visit(f uefi.Firmware) error {
	incr := func(m *map[string]int, key string) {
		if n, ok := (*m)[key]; ok {
			(*m)[key] = n + 1
		} else {
			(*m)[key] = 1
		}
	}

	incr(&v.FirmwareTypeCount, strings.TrimPrefix(fmt.Sprintf("%T", f), "*uefi."))
	if file, ok := f.(*uefi.File); ok {
		incr(&v.FileTypeCount, file.Type)
	}
	if sec, ok := f.(*uefi.Section); ok {
		incr(&v.SectionTypeCount, sec.Type)
	}
	return f.ApplyChildren(v)
}

func init() {
	RegisterCLI("count", "count the number of each firmware type", 0, func(args []string) (uefi.Visitor, error) {
		return &Count{
			W: os.Stdout,
		}, nil
	})
}
