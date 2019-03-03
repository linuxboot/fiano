// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// JSON prints any Firmware node as JSON.
type JSON struct {
	// JSON is written to this writer.
	W io.Writer
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *JSON) Run(f uefi.Firmware) error {
	return f.Apply(v)
}

// Visit applies the JSON visitor to any Firmware type.
func (v *JSON) Visit(f uefi.Firmware) error {
	b, err := json.MarshalIndent(f, "", "\t")
	if err != nil {
		return err
	}
	fmt.Fprintln(v.W, string(b))
	return nil
}

func init() {
	RegisterCLI("json", "produce JSON for the full firmware volume", 0, func(args []string) (uefi.Visitor, error) {
		return &JSON{
			W: Stdout,
		}, nil
	})
}
