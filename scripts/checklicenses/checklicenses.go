// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Run with `go run checklicenses.go`. This script has one drawback:
//   - It does not correct the licenses; it simply outputs a list of files which
//     do not conform and returns 1 if the list is non-empty.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var absPath = flag.Bool("a", false, "Print absolute paths")

const uroot = "$GOPATH/src/github.com/u-root/u-root"

// The first few lines of every go file is expected to contain this license.
var license = regexp.MustCompile(
	`^// Copyright [\d\-, ]+ the LinuxBoot Authors\. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file\.
`)

type rule struct {
	*regexp.Regexp
	invert bool
}

func accept(s string) rule {
	return rule{
		regexp.MustCompile("^" + s + "$"),
		false,
	}
}

func reject(s string) rule {
	return rule{
		regexp.MustCompile("^" + s + "$"),
		true,
	}
}

// A file is checked iff all the accepts and none of the rejects match.
var rules = []rule{
	accept(`.*\.go`),
	reject(`vendor/.*`), // Various authors
}

func main() {
	flag.Parse()
	uroot := os.ExpandEnv(uroot)
	incorrect := []string{}

	// List files added to u-root.
	out, err := exec.Command("git", "ls-files").Output()
	if err != nil {
		log.Fatalln("error running git ls-files:", err)
	}
	files := strings.Fields(string(out))

	// Iterate over files.
outer:
	for _, file := range files {
		// Test rules.
		trimmedPath := strings.TrimPrefix(file, uroot)
		for _, r := range rules {
			if r.MatchString(trimmedPath) == r.invert {
				continue outer
			}
		}

		// Make sure it is not a directory.
		info, err := os.Stat(file)
		if err != nil {
			log.Fatalln("cannot stat", file, err)
		}
		if info.IsDir() {
			continue
		}

		// Read from the file.
		r, err := os.Open(file)
		if err != nil {
			log.Fatalln("cannot open", file, err)
		}
		defer r.Close()
		contents, err := io.ReadAll(r)
		if err != nil {
			log.Fatalln("cannot read", file, err)
		}
		if !license.Match(contents) {
			p := trimmedPath
			if *absPath {
				p = file
			}
			incorrect = append(incorrect, p)
		}
	}
	if err != nil {
		log.Fatal(err)
	}

	// Print files with incorrect licenses.
	if len(incorrect) > 0 {
		fmt.Println(strings.Join(incorrect, "\n"))
		os.Exit(1)
	}
}
