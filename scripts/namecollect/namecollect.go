// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Run with `go run namecollect.go`. This updates the knownguids.go file with
// names from EDK2.
package main

import (
	"go/build"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/knownguids"
)

const knownGUIDsFile = "src/github.com/linuxboot/fiano/pkg/knownguids/guids.go"

var knownGUIDsTemplate = `// Copyright {{.Year}} the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package knownguids contains a list of guids and their names.
// THIS FILE IS GENERATED! DO NOT MODIFY!
// To regenerate, run: go run scripts/namecollect/namecollect.go
package knownguids

import "github.com/linuxboot/fiano/pkg/guid"

// GUIDs is a mapping from a GUID to its name.
var GUIDs = map[guid.GUID]string {
	{{- range .GUIDs}}
	*guid.MustParse({{printf "%q" .GUID}}): {{printf "%q" .Name}},
	{{- end}}
}
`

func getGUIDsFile() string {
	gopath := build.Default.GOPATH
	if gopath == "" {
		gopath = os.ExpandEnv("$HOME/go")
	}
	return filepath.Join(gopath, knownGUIDsFile)
}

func downloadEdk2() (tmpDir string, err error) {
	tmpDir, err = ioutil.TempDir("", "namecollect")
	if err != nil {
		return "", err
	}
	github := "https://github.com/tianocore/edk2"
	cmd := exec.Command("git", "clone", "--depth=1", github, tmpDir)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}
	return tmpDir, nil
}

func findGUIDs(dir string) (map[guid.GUID]string, error) {
	guids := map[guid.GUID]string{}
	baseNameRegex := regexp.MustCompile(`[\t ]*BASE_NAME[\t ]*=([^\n#]+)`)
	fileGUIDRegex := regexp.MustCompile(`[\t ]*FILE_GUID[\t ]*=([^\n#]+)`)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("skipping %q due to error: %v", path, err)
			return nil
		}
		if info.Mode().IsRegular() && strings.HasSuffix(path, ".inf") {
			contents, err := ioutil.ReadFile(path)
			if err != nil {
				log.Printf("skipping %q due to error: %v", path, err)
				return nil
			}
			baseNames := baseNameRegex.FindAllSubmatch(contents, -1)
			fileGUIDs := fileGUIDRegex.FindAllSubmatch(contents, -1)
			if len(baseNames) == 0 || len(fileGUIDs) == 0 {
				log.Printf("skipping %q because is does not contain BASE_NAME or FILE_GUID", path)
				return nil
			}
			if len(baseNames) != 1 || len(fileGUIDs) != 1 {
				log.Printf("skipping %q because it contains multiple of BASE_NAME or FILE_GUID", path)
				return nil
			}
			g, err := guid.Parse(strings.TrimSpace(string(fileGUIDs[0][1])))
			if err != nil {
				log.Printf("skipping %q because the GUID %q cannot be parsed: %v",
					path, fileGUIDs[0][1], err)
				return nil
			}
			name := strings.TrimSpace(string(baseNames[0][1]))
			if prevName, ok := guids[*g]; ok && prevName != name {
				log.Printf("warning %v has two names %q and %q", *g, prevName, name)
				return nil
			}
			guids[*g] = name
		}
		return nil
	})
	return guids, err
}

func main() {
	tmpl, err := template.New("knownguids").Parse(knownGUIDsTemplate)
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.Create(getGUIDsFile())
	if err != nil {
		log.Fatal(err)
	}

	tmpDir, err := downloadEdk2()
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	newGUIDs, err := findGUIDs(tmpDir)
	if err != nil {
		log.Fatal(err)
	}

	previousGUIDs := knownguids.GUIDs
	for guid, n := range previousGUIDs {
		if newGUIDs[guid] != n {
			log.Printf("warning %v name changed from %q to %q",
				guid, n, newGUIDs[guid])
		}
	}

	// Sort so the order is deterministic.
	type guidNamePair struct {
		GUID guid.GUID
		Name string
	}
	sortedGUIDs := []guidNamePair{}
	for k, v := range newGUIDs {
		sortedGUIDs = append(sortedGUIDs, guidNamePair{k, v})
	}
	sort.SliceStable(sortedGUIDs, func(i, j int) bool {
		return strings.Compare(sortedGUIDs[i].Name, sortedGUIDs[j].Name) < 0
	})

	err = tmpl.Execute(f, struct {
		Year  int
		GUIDs []guidNamePair
	}{
		Year:  time.Now().Year(),
		GUIDs: sortedGUIDs,
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatalln("error closing file:", err)
	}
}
