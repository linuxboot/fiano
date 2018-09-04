// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// ueficat will cat a set of files from a firmware volume.
// The files are specified with a regular expression that is
// matched against a file GUID.
//
// Synopsis:
//     ueficat <romimage> pat [pat ...]
//
// Description:
//     ueficat reads a firmware volume and, for every file in it, matches it
//     against the set of patterns passed in the command line.
//     The pat can be a simple re matching a GUID, or an re of the form re:re.
//     The optional second re matches a name in one of the sections, typically
//     an EFI_SECTION_USER_INTERFACE, though we don't currently check for section type.
//     If the pat matches the guid and name, and the file has a section of type EFI_SECTION_RAW,
//     that section is written to os.Stdout.
//     For example, in one UEFI image we have, we can say
//     ueficat 7:Initrd
//     and the initrd
//     is output to stdout. If we have a lot of confidence, we can even say .:Initrd or 7:I
package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/linuxboot/fiano/pkg/uefi"
	"github.com/linuxboot/fiano/pkg/visitors"
)

type pat struct {
	guid *regexp.Regexp
	name *regexp.Regexp
}

var pats []pat

//   File  74696E69-6472-632E-7069-6F2F62696F73  EFI_FV_FILETYPE_FREEFORM           3354174
//    Sec                                        EFI_SECTION_RAW                    3354116
//    Sec  Initrd                                EFI_SECTION_USER_INTERFACE         18
//    Sec                                        EFI_SECTION_VERSION                14
func pred(f *uefi.File, name string) bool {
	var guid = f.Header.UUID.String()
	for _, pat := range pats {
		if !pat.guid.MatchString(guid) {
			continue
		}
		for _, s := range f.Sections {
			if pat.name.MatchString(s.Name) {
				return true
			}
		}
	}
	return false
}

func main() {
	flag.Parse()
	if flag.NArg() < 2 {
		log.Fatal("ueficat <uefi file> re[:[re]] <...re[:[re]] # e.g. 74696E69-6472-632E-7069-6F2F62696F73 or 7:Initrd")
	}

	b, err := ioutil.ReadFile(flag.Args()[0])
	if err != nil {
		log.Fatal(err)
	}
	f, err := uefi.Parse(b)
	if err != nil {
		log.Fatal(err)
	}
	for _, a := range flag.Args()[1:] {
		var p pat
		switch args := strings.Split(a, ":"); len(args) {
		case 2:
			p.name = regexp.MustCompile(args[1])
			p.guid = regexp.MustCompile(args[0])
		case 1:
			p.name = regexp.MustCompile(".")
			p.guid = regexp.MustCompile(args[0])
		default:
			log.Fatalf("%s: more than one :", a)
		}
		pats = append(pats, p)
	}

	u := &visitors.Find{Predicate: pred}

	if err := u.Visit(f); err != nil {
		log.Fatal(err)
	}

	for _, m := range u.Matches {
		for _, s := range m.Sections {
			if s.Type == "EFI_SECTION_RAW" {
				// Skip the four bytes of junk at the front. We don't care.
				if _, err := os.Stdout.Write(s.Buf()[4:]); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}
