// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha1"
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
	depex      = flag.String("depex", "", "Space-separated protocol guid dependencies or TRUE")
	compress   = flag.Bool("compress", false, "Wrap section data in a compressed section")
	auto       = flag.Bool("auto", false, "Attempt to determine section types from file extensions")

	fType  uefi.FVFileType
	fGUID  *guid.GUID
	depOps []uefi.DepExOp
	printf = func(string, ...interface{}) {}
)

const (
	usageString = "Usage: create-ffs [flags] file.efi [...]"
)

func createDepExes(deps string) ([]uefi.DepExOp, error) {
	var err error
	ops := []uefi.DepExOp{}

	if strings.ToUpper(deps) == "TRUE" {
		// Create just "TRUE" and "END" for now, but this feels unnecessary to me.
		ops = append(ops, uefi.DepExOp{OpCode: "TRUE"})
		ops = append(ops, uefi.DepExOp{OpCode: "END"})
		return ops, nil
	}

	// we expect a space-separated list of GUIDs
	guids := strings.Split(deps, " ")
	numGUIDS := len(guids)
	for _, guidStr := range guids {
		var g *guid.GUID

		if g, err = guid.Parse(guidStr); err != nil {
			return nil, err
		}
		printf("depex guid requested: %v", *g)
		ops = append(ops, uefi.DepExOp{OpCode: "PUSH", GUID: g})
	}

	// Append an "AND" for n-1 pushes.
	for i := 1; i < numGUIDS; i++ {
		ops = append(ops, uefi.DepExOp{OpCode: "AND"})
	}

	ops = append(ops, uefi.DepExOp{OpCode: "END"})
	return ops, nil
}

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
	} else if *name != "" {
		// We sha1 the name to get a reproducible GUID.
		fGUID = &guid.GUID{}
		sum := sha1.Sum([]byte(*name))
		copy(fGUID[:], sum[:guid.Size])
	} else {
		return errors.New("no GUID or name provided, please provide at least one")
	}

	if *outfile == "" {
		return errors.New("we don't currently support dumping to stdout, please specify an output file")
	}

	if *depex != "" {
		depOps, err = createDepExes(*depex)
		if err != nil {
			return fmt.Errorf("can't parse depex guids, got %v", err)
		}
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
	mainSection.SetType(secType)
	mainSection.SetBuf(secData)
	mainSection.GenSecHeader()
	file.Sections = append(file.Sections, mainSection)
	printf("selected section type: %v", mainSection.Header.Type)

	if *name != "" {
		s := &uefi.Section{}
		s.SetType(uefi.SectionTypeUserInterface)
		s.Name = *name
		file.Sections = append(file.Sections, s)
	}

	if *version != "" {
		s := &uefi.Section{}
		s.SetType(uefi.SectionTypeVersion)
		s.Version = *version
		file.Sections = append(file.Sections, s)
	}

	if *depex != "" {
		s := &uefi.Section{}
		s.SetType(uefi.SectionTypeDXEDepEx)
		s.DepEx = depOps
		file.Sections = append(file.Sections, s)
	}

	save := &visitors.Save{DirPath: *outfile}

	err = file.Apply(save)
	if err != nil {
		log.Fatal(err)
	}

	if *debug {
		// Dump file json for checking
		jsonv := &visitors.JSON{W: os.Stdout}
		if err = file.Apply(jsonv); err != nil {
			log.Fatal(err)
		}
	}
}
