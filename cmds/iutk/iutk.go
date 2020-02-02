// Copyright 2020 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"html"
	"regexp"
	"fmt"
	"log"
	"syscall/js"
	"strings"

	"github.com/linuxboot/fiano/pkg/uefi"
	"github.com/linuxboot/fiano/pkg/visitors"
	"github.com/dennwc/dom"
)

type FirmwareTree struct {
	nodes []visitors.FlattenedFirmware
}

func (t *FirmwareTree) NumRows() int {
	return len(t.nodes)
}

func (t *FirmwareTree) NumCols() int {
	return 3
}

func (t *FirmwareTree) Text(row int, col int) string {
	f := t.nodes[row].Value
	switch col {
		case 0:
			return t.nodes[row].Type
		case 1:
			switch f := f.(type) {
			case *uefi.FirmwareVolume:
				return f.String()
			case *uefi.File:
				return f.Header.GUID.String()
			case *uefi.Section:
				return f.String()
			case *uefi.NVar:
				return f.GUID.String()
			case *uefi.RawRegion:
				return f.Type().String()
			}
		case 2:
			switch f := f.(type) {
			case *uefi.File:
				return f.Header.Type.String()
			case *uefi.Section:
				return f.Type
			}
	}
	return ""
}

func (t *FirmwareTree) Level(row int) int {
	return t.nodes[row].Level
}

func (t *FirmwareTree) OnClick(row int, _ *dom.MouseEvent) {
	json, err := json.MarshalIndent(t.nodes[row].Value, "", "    ")
	if err != nil {
		log.Print(err)
	}
	dom.Doc.GetElementById("node-info-pane").SetInnerHTML(string(json))
}

func load(image []byte) {
	// Parse the image.
	root, err := uefi.Parse(image)
	if err != nil {
		log.Print(err)
	}

	updateList := func() {
		// Clone via encode/decode to get around the destructive nature of
		// flatten.
		var clone uefi.Firmware
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(&root); err != nil {
			log.Printf("error encoding: %v", err)
			return
		}
		if err := gob.NewDecoder(&buf).Decode(&clone); err != nil {
			log.Printf("error decoding: %v", err)
			return
		}

		// Flatten the tree otherwise JavaScript would be unable to tell which
		// objects are uefi.Firmware.
		flatten := visitors.Flatten{}
		if err := flatten.Run(clone); err != nil {
			log.Fatal(err)
		}


		// Create a new table.
		tree := dom.Doc.GetElementById("tree")
		NewTree(tree, &FirmwareTree{flatten.List})
	}

	updateVisitors := func() {
		newWord := regexp.MustCompile(`_|\b`)
		for name, v := range visitors.VisitorRegistry {
			name := name // for closure capture
			text := newWord.ReplaceAllStringFunc(name, func(src string) string  {
				if src == "_" {
					return " "
				}
				return strings.ToUpper(src)
			})
			text = fmt.Sprintf("%s (%d)", text, v.NumArgs)

			button := dom.NewButton(html.EscapeString(text))
			button.SetAttribute("title", v.Help)
			button.OnClick(func (_ dom.Event) {
				defer updateList()

				entry, ok := visitors.VisitorRegistry[name]
				if !ok {
					log.Printf("Error: visitor %q not found", name)
					return
				}
				args := []string{} // TODO: Support multiple args
				if entry.NumArgs != len(args) {
					log.Printf("Error: bad number of arguments, expected %d, got %d",
						entry.NumArgs, len(args))
					return
				}
				v, err := entry.CreateVisitor(args)
				if err != nil {
					log.Fatal(err)
				}
				if err := v.Run(root); err != nil {
					log.Fatal(err)
				}
				log.Println("Ran command", name, args)
			})
			dom.Doc.GetElementById("visitors").AppendChild(button)
		}
	}

	updateVisitors()
	updateList()

	// Make the workspace visible.
	dom.Doc.GetElementById("workspace").AsHTMLElement().Style().Set("display", "block")
}

func main() {
	log.Println("Welcome to iUTK!")

	p1 := dom.Doc.CreateElement("p")
	p1.SetTextContent("Welcome to iUTK! Please open a file.")
	dom.Body.AppendChild(p1)

	input := dom.NewInput("file")
	input.OnChange(func(e dom.Event) {
		// You can program JavaScript in any language :)
		// Get the JS File object from the <input> tag's files attribute.
		files := e.JSValue().Get("target").Get("files")
		if files.Type() != js.TypeObject || files.Length() == 0 {
			log.Print("No files specified")
			return
		}
		file := files.Index(0)
		log.Printf("Reading file %q...", file.Get("name").String())

		// Read the contents of the file asynchronously.
		reader := js.Global().Get("FileReader").New()
		var onload, onerror js.Func
		onload = js.FuncOf(func(_ js.Value, _ []js.Value) interface {} {
			onload.Release()
			onerror.Release()
			var arrayBuffer = reader.Get("result")
			var uint8Array = js.Global().Get("Uint8Array").New(arrayBuffer)
			data := make([]byte, uint8Array.Get("length").Int())
			n := js.CopyBytesToGo(data, uint8Array)
			log.Printf("File read, %d bytes", n)
			load(data)
			return nil
		})
		onerror = js.FuncOf(func(this js.Value, args []js.Value) interface {} {
			onload.Release()
			onerror.Release()
			log.Print("Error: failed to read file")
			return nil
		})
		reader.Set("onload", onload)
		reader.Set("onerror", onerror)
		reader.Call("readAsArrayBuffer", file)
	})
	dom.Body.AppendChild(input)

	dom.Loop()
}
