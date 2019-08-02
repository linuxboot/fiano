// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package guid2english provides a transform.Transformer which replaces all
// GUIDs in the input with their known English representation.
package guid2english

import (
	"bytes"
	"log"
	"regexp"
	"text/template"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/knownguids"
	"golang.org/x/text/transform"
)

var guidRegex = regexp.MustCompile(
	"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}",
)

// Mapper converts a GUID to a string.
type Mapper interface {
	Map(guid.GUID) []byte
}

// TemplateMapper implements mapper using Go's text/template package. The
// template can refer to the following variables:
//   * {{.Guid}}: The GUID being mapped
//   * {{.Name}}: The English name of the GUID or "UNKNOWN"
//   * {{.IsKnown}}: Set to true when the English name is not known
type TemplateMapper struct {
	tmpl *template.Template
}

// NewTemplateMapper creates a new TemplateMapper given a Template.
func NewTemplateMapper(tmpl *template.Template) *TemplateMapper {
	return &TemplateMapper{
		tmpl: tmpl,
	}
}

// Map implements the Mapper.Map() function.
func (f *TemplateMapper) Map(g guid.GUID) []byte {
	name, isKnown := knownguids.GUIDs[g]
	if !isKnown {
		name = "UNKNOWN"
	}

	b := &bytes.Buffer{}
	err := f.tmpl.Execute(b, struct {
		GUID    guid.GUID
		Name    string
		IsKnown bool
	}{
		GUID:    g,
		Name:    name,
		IsKnown: isKnown,
	})
	if err != nil {
		// There is likely a bug in the template. We do not want to
		// interrupt the byte stream, so just log the error.
		log.Printf("Error in template: %v", err)
	}
	return b.Bytes()
}

// Transformer replaces all the GUIDs using the Mapper interface. For example,
// this can replace all the GUIDs with their's English representation.
type Transformer struct {
	mapper Mapper
}

// New creates a new Transformer with the given Mapper.
func New(m Mapper) *Transformer {
	return &Transformer{
		mapper: m,
	}
}

// Transform implements transform.Transformer.Transform().
func (t *Transformer) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	transformed := guidRegex.ReplaceAllFunc(src, func(match []byte) []byte {
		// The regex only matches valid GUIDs, so this must parse.
		g, err := guid.Parse(string(match))
		if err != nil {
			return src
		}
		return t.mapper.Map(*g)
	})
	if len(transformed) > len(dst) {
		return 0, 0, transform.ErrShortDst
	}
	copy(dst, transformed)
	return len(transformed), len(src), nil
}

// Reset implements transform.Transformer.Reset().
func (t *Transformer) Reset() {
}
