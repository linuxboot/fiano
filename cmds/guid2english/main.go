// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// guid2english replace GUIDs with their English representation.
//
// Synopsis:
//     guid2english [-t TEMPLATE] [FILE]
//
// Options:
//     -t TEMPLATE:
//         A template used to replace GUIDS. The template can refer to the
//         following variables:
//             * {{.Guid}}: The GUID being mapped
//             * {{.Name}}: The English name of the GUID or "UNKNOWN"
//             * {{.IsKnown}}: Set to true when the English name is not known
//         The default template is "{{.GUID}} ({{.Name}})".
//
// Description:
//     If FILE is not specified, stdin is used.
package main

import (
	"flag"
	"io"
	"os"
	"text/template"

	"github.com/linuxboot/fiano/pkg/guid2english"
	"github.com/linuxboot/fiano/pkg/log"
	"golang.org/x/text/transform"
)

var (
	tmpl = flag.String("t", "{{.GUID}} ({{.Name}})", "template string")
)

func main() {
	flag.Parse()
	r := os.Stdin
	switch flag.NArg() {
	case 0:
	case 1:
		var err error
		r, err = os.Open(flag.Arg(0))
		if err != nil {
			log.Fatalf("Error opening file: %v", err)
		}
		defer r.Close()
	default:
		log.Fatalf("At most 1 positional arguments expected")
	}

	t, err := template.New("guid2english").Parse(*tmpl)
	if err != nil {
		log.Fatalf("Template not valid: %v", err)
	}

	trans := guid2english.New(guid2english.NewTemplateMapper(t))

	_, err = io.Copy(os.Stdout, transform.NewReader(r, trans))
	if err != nil {
		log.Fatalf("Error copying buffer: %v", err)
	}
}
