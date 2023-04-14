// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/linuxboot/fiano/pkg/cbfs"
	flag "github.com/spf13/pflag"
)

var debug = flag.BoolP("debug", "d", false, "enable debug prints")

func main() {
	flag.Parse()

	if *debug {
		cbfs.Debug = log.Printf
	}

	a := flag.Args()
	if len(a) < 2 {
		log.Fatal("Usage: cbfs <firmware-file> <json,list,extract <directory-name>>")
	}

	i, err := cbfs.Open(a[0])
	if err != nil {
		log.Fatal(err)
	}

	switch a[1] {
	case "list":
		fmt.Printf("%s", i.String())
	case "json":
		j, err := json.MarshalIndent(i, "  ", "  ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", string(j))
	case "extract":
		if len(a) != 3 {
			log.Fatal("provide a directory name")
		}
		dir := filepath.Join(".", a[2])
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			log.Fatal(err)
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
				fpath := filepath.Join(dir, strings.Replace(n, "/", "_", -1))
				d, err := f.Decompress()
				if err != nil {
					log.Fatal(err)
				}
				err = os.WriteFile(fpath, d, 0644)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	default:
		log.Fatal("?")
	}

}
