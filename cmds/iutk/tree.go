// Copyright 2020 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"strings"
	"html"

	"github.com/dennwc/dom"
)

type TreeData interface {
	NumRows() int
	NumCols() int
	Text(row int, col int) string
	Level(row int) int
	OnClick(row int, e *dom.MouseEvent)
}

type Tree struct {
	parent *dom.Element
	data TreeData
	highlighted *dom.Element
}

func NewTree(parent *dom.Element, data TreeData) *Tree {
	t := &Tree {
		parent: parent,
		data: data,
	}
	t.Recreate()
	return t
}

func (t *Tree) Recreate() {
	// Clear existing DOM.
	t.parent.SetInnerHTML("")

	table := dom.Doc.CreateElement("table")

	numRows := t.data.NumRows()
	numCols := t.data.NumCols()
	for i := 0; i < numRows; i++ {
		i := i // for closure capture
		tr := dom.Doc.CreateElement("tr")
		tr.OnClick(func (e *dom.MouseEvent) {
			if t.highlighted != nil {
				t.highlighted.ClassList().Remove("highlight")
			}
			t.highlighted = tr
			t.highlighted.ClassList().Add("highlight")
			t.data.OnClick(i, e)
		})

		for j := 0; j < numCols; j++ {
			indent := ""
			if j == 0 {
				indent = strings.Repeat("_", t.data.Level(i))
			}
			tdType := dom.Doc.CreateElement("td")
			tdType.AsHTMLElement().SetInnerText(html.EscapeString(indent + t.data.Text(i, j)))
			tr.AppendChild(tdType)
		}
		table.AppendChild(tr)
	}
	t.parent.AppendChild(table)
}
