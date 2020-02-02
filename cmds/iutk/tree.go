// Copyright 2020 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"html"
	"fmt"

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
	selected *dom.Element
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
			if t.selected != nil {
				t.selected.ClassList().Remove("selected")
			}
			t.selected = tr
			t.selected.ClassList().Add("selected")
			t.data.OnClick(i, e)
		})

		for j := -1; j < numCols; j++ {
			td := dom.Doc.CreateElement("td")
			label := dom.Doc.CreateElement("label")
			if j != -1 {
				label.SetInnerHTML(html.EscapeString(t.data.Text(i, j)))
			}
			label.SetAttribute("for", fmt.Sprintf("checkbox%d", i))
			td.AppendChild(label)
			if j == 0 {
				label.AsHTMLElement().Style().Set("padding-left", fmt.Sprintf("%fem", float32(t.data.Level(i)) / 2))
			}
			if j == -1 {
				checkbox := dom.NewInput("checkbox")
				checkbox.SetId(fmt.Sprintf("checkbox%d", i))
				checkbox.OnChange(func (dom.Event) {
					if checkbox.JSValue().Get("checked").Bool() {
						tr.ClassList().Add("highlighted")
					} else {
						tr.ClassList().Remove("highlighted")
					}
				})
				label.AppendChild(checkbox)
			}
			tr.AppendChild(td)
		}
		table.AppendChild(tr)
	}
	t.parent.AppendChild(table)
}
