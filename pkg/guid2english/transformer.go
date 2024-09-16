// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package guid2english provides a transform.Transformer which replaces all
// GUIDs in the input with their known English representation.
package guid2english

import (
	"bytes"
	"regexp"
	"text/template"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/knownguids"
	"github.com/linuxboot/fiano/pkg/log"
	"golang.org/x/text/transform"
)

var guidRegex = regexp.MustCompile(
	"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}",
)

var partialguidRegex = regexp.MustCompile(
	"[-a-fA-F0-9]{1,36}$",
)

// Mapper converts a GUID to a string.
type Mapper interface {
	Map(guid.GUID) []byte
}

// TemplateMapper implements mapper using Go's text/template package. The
// template can refer to the following variables:
//   - {{.Guid}}: The GUID being mapped
//   - {{.Name}}: The English name of the GUID or "UNKNOWN"
//   - {{.IsKnown}}: Set to true when the English name is not known
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
		log.Errorf("Error in template: %v", err)
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

func (t *Transformer) bufferMap(match []byte) []byte {
	// The regex only matches valid GUIDs, so this must parse.
	g, err := guid.Parse(string(match))
	if err != nil {
		return match
	}
	return t.mapper.Map(*g)
}

// Transform implements transform.Transformer.Transform().
func (t *Transformer) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	if atEOF {
		// we have the end of file, try to process all at once
		transformed := guidRegex.ReplaceAllFunc(src, t.bufferMap)
		if len(transformed) > len(dst) {
			// we were too optimistic, dst is too short
			d, s, e := t.Transform(dst, src, false)
			if e != transform.ErrShortSrc {
				return d, s, e
			}
			return d, s, transform.ErrShortDst
		}
		copy(dst, transformed)
		return len(transformed), len(src), nil
	}
	loc := guidRegex.FindIndex(src)
	if loc == nil {
		// check if the end potentially contain the beginning of a GUID
		loc := partialguidRegex.FindIndex(src)
		if loc == nil {
			copy(dst, src)
			return len(src), len(src), nil
		}
		copy(dst, src[0:loc[0]])
		return loc[0], loc[0], transform.ErrShortSrc
	}
	copy(dst, src[0:loc[0]])
	mappedGUID := t.bufferMap(src[loc[0]:loc[1]])
	if loc[0]+len(mappedGUID) > len(dst) {
		// mapped buffer does not fit, only send the plain part
		return loc[0], loc[0], transform.ErrShortDst
	}

	copy(dst[loc[0]:], mappedGUID)
	return loc[0] + len(mappedGUID), loc[1], transform.ErrShortSrc
}

// Reset implements transform.Transformer.Reset().
func (t *Transformer) Reset() {
}
