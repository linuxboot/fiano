// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/linuxboot/fiano/pkg/cbfs"
	flag "github.com/spf13/pflag"
)

var debug = flag.BoolP("debug", "d", false, "enable debug prints")

var errUsage = errors.New("usage: cbfs <firmware-file> <json,list,extract <directory-name>>")
var errMissingDirectory = errors.New("provide a directory name")

func run(stdout io.Writer, debug bool, args []string) error {
	if debug {
		cbfs.Debug = log.Printf
	}

	if len(args) < 2 {
		return errUsage
	}

	i, err := cbfs.Open(args[0])
	if err != nil {
		return err
	}

	switch args[1] {
	case "list":
		fmt.Fprintf(stdout, "%s", i.String())
	case "json":
		j, err := json.MarshalIndent(i, "  ", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s", string(j))
	case "extract":
		if len(args) != 3 {
			return errMissingDirectory
		}
		dir := filepath.Join(".", args[2])
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return err
		}

		base := i.Area.Offset
		log.Printf("FMAP base at %x", base)
		for s := range i.Segs {
			f := i.Segs[s].GetFile()
			n := f.Name
			c := f.Compression()
			o := f.RecordStart
			if f.Type.String() == cbfs.TypeDeleted.String() || f.Type.String() == cbfs.TypeDeleted2.String() {
				log.Printf("Skipping empty/deleted file at 0x%x", o)
			} else {
				log.Printf("Extracting %v from 0x%x, compression: %v", n, o, c)
				fpath := filepath.Join(dir, strings.ReplaceAll(n, "/", "_"))
				d, err := f.Decompress()
				if err != nil {
					return err
				}
				err = os.WriteFile(fpath, d, 0644)
				if err != nil {
					return err
				}
			}
		}
	default:
		return errUsage
	}

	return nil
}

func main() {
	flag.Parse()
	if err := run(os.Stdout, *debug, flag.Args()); err != nil {
		log.Fatal(err)
	}
}
