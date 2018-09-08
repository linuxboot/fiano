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
	W io.Writer

	// Output
	Count map[string]int
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Count) Run(f uefi.Firmware) error {
	if v.Count == nil {
		v.Count = map[string]int{}
	}

	if err := f.Apply(v); err != nil {
		return err
	}

	if v.W != nil {
		b, err := json.MarshalIndent(v.Count, "", "\t")
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
	firmwareType := strings.TrimPrefix(fmt.Sprintf("%T", f), "*uefi.")
	if n, ok := v.Count[firmwareType]; ok {
		v.Count[firmwareType] = n + 1
	} else {
		v.Count[firmwareType] = 1
	}
	return f.ApplyChildren(v)
}

func init() {
	RegisterCLI("count", 0, func(args []string) (uefi.Visitor, error) {
		return &Count{
			W: os.Stdout,
		}, nil
	})
}
