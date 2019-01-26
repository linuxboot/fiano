// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/uefi"
	"github.com/linuxboot/fiano/pkg/visitors"
)

var (
	debug      = flag.Bool("d", false, "Enable debug prints")
	outfile    = flag.String("o", "", "output file, default is stdout")
	name       = flag.String("name", "", "Name to include in UI section")
	filetype   = flag.String("type", "DRIVER", "UEFI filetype")
	version    = flag.String("version", "1.0", "File version")
	guidString = flag.String("guid", "", "File GUID")
	compress   = flag.Bool("compress", false, "Wrap section data in a compressed section")
	auto       = flag.Bool("auto", false, "Attempt to determine section types from file extensions")

	fType  uefi.FVFileType
	fGUID  *guid.GUID
	printf = func(string, ...interface{}) {}
)

const (
	usageString = "Usage: create-ffs [flags] file.efi [...]"
)

func parseFlags() error {
	var ok bool
	var err error

	if *debug {
		printf = log.Printf
	}

	// Check filetypes
	fType, ok = uefi.NamesToFileType[*filetype]
	if !ok {
		validTypes := []string{}
		for k := range uefi.NamesToFileType {
			validTypes = append(validTypes, k)
		}
		return fmt.Errorf("unable to get EFI File type, got %v, expected values in\n{%v}",
			*filetype, strings.Join(validTypes, ", "))
	}

	if *guidString != "" {
		fGUID, err = guid.Parse(*guidString)
		if err != nil {
			return err
		}
	} else {
		//TODO: we should sha1 the name, for now just pick a default
		fGUID = guid.MustParse("DECAFBAD-6548-6461-732d-2f2d4e455246")
	}

	if *outfile == "" {
		return errors.New("we don't currently support dumping to stdout, please specify an output file")
	}

	return nil
}

func usage() {
	log.Print(usageString)
	flag.PrintDefaults()
	os.Exit(1)
}

func main() {
	flag.Parse()
	if err := parseFlags(); err != nil {
		log.Fatal(err)
	}

	args := flag.Args()
	if alen := len(args); alen < 1 {
		usage()
	}

	secData, err := ioutil.ReadFile(args[0])
	if err != nil {
		log.Fatal(err)
	}

	printf("type requested: %v", fType)
	printf("name requested: %v", *name)
	printf("version requested: %v", *version)
	printf("guid: %v", fGUID)

	secType := uefi.SectionTypeRaw
	switch fType {
	case uefi.FVFileTypeApplication, uefi.FVFileTypeCombinedSMMDXE,
		uefi.FVFileTypeCombinedPEIMDriver, uefi.FVFileTypeDriver:
		secType = uefi.SectionTypePE32
	}

	file := &uefi.File{}
	file.Header.Type = fType
	file.Header.GUID = *fGUID

	mainSection := &uefi.Section{}
	mainSection.Header.Type = secType
	mainSection.SetBuf(secData)
	mainSection.GenSecHeader()
	file.Sections = append(file.Sections, mainSection)
	printf("selected section type: %v", mainSection.Header.Type)

	if *name != "" {
		uiSection := &uefi.Section{}
		uiSection.Header.Type = uefi.SectionTypeUserInterface
		uiSection.Name = *name
		file.Sections = append(file.Sections, uiSection)
	}

	if *version != "" {
		vSection := &uefi.Section{}
		vSection.Header.Type = uefi.SectionTypeVersion
		vSection.Version = *version
		file.Sections = append(file.Sections, vSection)
	}

	// TODO: handle depex

	save := &visitors.Save{DirPath: *outfile}

	err = file.Apply(save)
	if err != nil {
		log.Fatal(err)
	}
}
