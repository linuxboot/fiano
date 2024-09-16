// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Fmap parses flash maps.
//
// Synopsis:
//
//	fmap checksum [md5|sha1|sha256] FILE
//	fmap extract [index|name] FILE
//	fmap jget JSONFILE FILE
//	fmap jput JSONFILE FILE
//	fmap summary FILE
//	fmap usage FILE
//	fmap verify FILE
//
// Description:
//
//	checksum: Print a checksum using the given hash function.
//	extract:  Print the i-th area or area name from the flash.
//	jget:     Write json representation of the fmap to JSONFILE.
//	jput:     Replace current fmap with json representation in JSONFILE.
//	summary:  Print a human readable summary.
//	usage:    Print human readable usage stats.
//	verify:   Return 1 if the flash map is invalid.
//
//	This implementation is based off of https://github.com/dhendrix/flashmap.
package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"text/template"

	"github.com/linuxboot/fiano/pkg/fmap"
	"github.com/linuxboot/fiano/pkg/log"
)

var cmds = map[string]struct {
	nArgs               int
	openFile, parseFMap bool
	f                   func(a cmdArgs) error
}{
	"checksum": {1, true, true, checksum},
	"extract":  {1, true, true, extract},
	"jget":     {1, true, true, jsonGet},
	"jput":     {1, false, false, jsonPut},
	"summary":  {0, true, true, summary},
	"usage":    {0, true, false, usage},
	"jusage":   {0, true, false, jusage},
	"verify":   {0, true, true, verify},
}

type cmdArgs struct {
	args []string
	f    *fmap.FMap     // optional
	m    *fmap.Metadata // optional
	r    *os.File
}

var hashFuncs = map[string](func() hash.Hash){
	"md5":    md5.New,
	"sha1":   sha1.New,
	"sha256": sha256.New,
}

type jsonSchema struct {
	FMap     *fmap.FMap
	Metadata *fmap.Metadata
}

// Print a checksum using the given hash function.
func checksum(a cmdArgs) error {
	if _, ok := hashFuncs[a.args[0]]; !ok {
		msg := "Not a valid hash function. Must be one of:"
		for k := range hashFuncs {
			msg += " " + k
		}
		return errors.New(msg)
	}

	checksum, err := a.f.Checksum(a.r, hashFuncs[a.args[0]]())
	if err != nil {
		return err
	}
	fmt.Printf("%x\n", checksum)
	return nil
}

// Print the i-th area of the flash.
func extract(a cmdArgs) error {
	i, err := strconv.Atoi(a.args[0])
	if err != nil {
		i = a.f.IndexOfArea(a.args[0])
		if i == -1 {
			return fmt.Errorf("area %q not found", a.args[0])
		}
	}
	area, err := a.f.ReadArea(a.r, i)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(area)
	return err
}

// Write json representation of the fmap to JSONFILE.
func jsonGet(a cmdArgs) error {
	data, err := json.MarshalIndent(jsonSchema{a.f, a.m}, "", "\t")
	if err != nil {
		return err
	}
	data = append(data, byte('\n'))
	return os.WriteFile(a.args[0], data, 0666)
}

// Replace current fmap with json representation in JSONFILE.
func jsonPut(a cmdArgs) error {
	r, err := os.OpenFile(os.Args[len(os.Args)-1], os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	defer r.Close()

	data, err := os.ReadFile(a.args[0])
	if err != nil {
		return err
	}
	j := jsonSchema{}
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	return fmap.Write(r, j.FMap, j.Metadata)
}

// Print a human readable summary.
func summary(a cmdArgs) error {
	const desc = `Fmap found at {{printf "%#x" .Metadata.Start}}:
	Signature:  {{printf "%s" .Signature}}
	VerMajor:   {{.VerMajor}}
	VerMinor:   {{.VerMinor}}
	Base:       {{printf "%#x" .Base}}
	Size:       {{printf "%#x" .Size}}
	Name:       {{.Name}}
	NAreas:     {{.NAreas}}
{{- range $i, $v := .Areas}}
	Areas[{{$i}}]:
		Offset:  {{printf "%#x" $v.Offset}}
		Size:    {{printf "%#x" $v.Size}}
		Name:    {{$v.Name}}
		Flags:   {{printf "%#x" $v.Flags}} ({{FlagNames $v.Flags}})
{{- end}}
`
	t := template.Must(template.New("desc").
		Funcs(template.FuncMap{"FlagNames": fmap.FlagNames}).
		Parse(desc))
	// Combine the two structs to pass into template.
	combined := struct {
		*fmap.FMap
		Metadata *fmap.Metadata
	}{a.f, a.m}
	return t.Execute(os.Stdout, combined)
}

// Print human readable usage stats.
func usage(a cmdArgs) error {
	blockSize := 4 * 1024
	rowLength := 32

	buffer := make([]byte, blockSize)
	fullBlock := bytes.Repeat([]byte{0xff}, blockSize)
	zeroBlock := bytes.Repeat([]byte{0x00}, blockSize)

	fmt.Println("Legend: '.' - full (0xff), '0' - zero (0x00), '#' - mixed")

	if _, err := a.r.Seek(0, io.SeekStart); err != nil {
		return err
	}

	var numBlocks, numFull, numZero int
loop:
	for {
		fmt.Printf("%#08x: ", numBlocks*blockSize)
		for col := 0; col < rowLength; col++ {
			// Read next block.
			_, err := io.ReadFull(a.r, buffer)
			if err == io.EOF {
				fmt.Print("\n")
				break loop
			} else if err == io.ErrUnexpectedEOF {
				fmt.Printf("\nWarning: flash is not a multiple of %d", len(buffer))
				break loop
			} else if err != nil {
				return err
			}
			numBlocks++

			// Analyze block.
			if bytes.Equal(buffer, fullBlock) {
				numFull++
				fmt.Print(".")
			} else if bytes.Equal(buffer, zeroBlock) {
				numZero++
				fmt.Print("0")
			} else {
				fmt.Print("#")
			}
		}
		fmt.Print("\n")
	}

	// Print usage statistics.
	print := func(name string, n int) {
		fmt.Printf("%s %d (%.1f%%)\n", name, n,
			float32(n)/float32(numBlocks)*100)
	}
	print("Blocks:      ", numBlocks)
	print("Full (0xff): ", numFull)
	print("Empty (0x00):", numZero)
	print("Mixed:       ", numBlocks-numFull-numZero)
	return nil
}

type rowEntry struct {
	Entries []string `json:"entries"`
	Address string   `json:"address"`
}
type flashLaout struct {
	Data   []rowEntry `json:"layout"`
	Blocks int        `json:"blocks"`
	Full   int        `json:"full"`
	Zero   int        `json:"zero"`
	Used   int        `json:"used"`
}

// Print machine readable usage stats.
func jusage(a cmdArgs) error {
	blockSize := 4 * 1024
	rowLength := 32

	buffer := make([]byte, blockSize)
	fullBlock := bytes.Repeat([]byte{0xff}, blockSize)
	zeroBlock := bytes.Repeat([]byte{0x00}, blockSize)

	if _, err := a.r.Seek(0, io.SeekStart); err != nil {
		return err
	}

	var numBlocks, numFull, numZero int

	var layout flashLaout

loop:
	for {
		var row rowEntry
		row.Address = fmt.Sprintf("%#08x", numBlocks*blockSize)
		for col := 0; col < rowLength; col++ {
			// Read next block.
			_, err := io.ReadFull(a.r, buffer)
			if err == io.EOF {
				break loop
			} else if err == io.ErrUnexpectedEOF {
				fmt.Printf("\nWarning: flash is not a multiple of %d", len(buffer))
				break loop
			} else if err != nil {
				return err
			}
			numBlocks++

			// Analyze block.
			if bytes.Equal(buffer, fullBlock) {
				numFull++
				row.Entries = append(row.Entries, "full")
			} else if bytes.Equal(buffer, zeroBlock) {
				numZero++
				row.Entries = append(row.Entries, "zero")
			} else {
				row.Entries = append(row.Entries, "used")
			}
		}
		layout.Data = append(layout.Data, row)
	}
	layout.Blocks = numBlocks
	layout.Full = numFull
	layout.Zero = numZero
	layout.Used = numBlocks - numFull - numZero

	// fmt.Printf("%s\n%s\n", layout.data[0].address, layout.data[0].entries[0])
	data, err := json.MarshalIndent(layout, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// Return 1 if the flash map is invalid.
func verify(a cmdArgs) error {
	var err error
	for i, area := range a.f.Areas {
		if area.Offset+area.Size > a.f.Size {
			err = errors.New("invalid flash map")
			log.Errorf("Area %d is out of range", i)
		}
	}
	return err
}

func printUsage() {
	fmt.Printf("Usage: %s CMD [ARGS...] FILE\n", os.Args[0])
	fmt.Printf("CMD can be one of:\n")
	for k := range cmds {
		fmt.Printf("\t%s\n", k)
	}
	os.Exit(2)
}

func main() {
	// Validate args.
	if len(os.Args) <= 2 {
		printUsage()
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		log.Errorf("Invalid command %#v\n", os.Args[1])
		printUsage()
	}
	if len(os.Args) != cmd.nArgs+3 {
		log.Errorf("Expected %d arguments, got %d\n", cmd.nArgs+3, len(os.Args))
		printUsage()
	}

	// Args passed to the command.
	a := cmdArgs{
		args: os.Args[2 : len(os.Args)-1],
	}

	// Open file, but only for specific commands.
	if cmd.openFile {
		// Open file.
		r, err := os.Open(os.Args[len(os.Args)-1])
		if err != nil {
			log.Fatalf("%v", err)
		}
		a.r = r
		defer r.Close()
	}

	// Parse fmap, but only for specific commands.
	if cmd.parseFMap {
		// Parse fmap.
		f, m, err := fmap.Read(a.r)
		if err != nil {
			log.Fatalf("%v", err)
		}
		a.f, a.m = f, m
	}

	// Execute command.
	if err := cmd.f(a); err != nil {
		log.Fatalf("%v", err)
	}
}
