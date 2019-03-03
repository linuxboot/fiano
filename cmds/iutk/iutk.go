// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/linuxboot/fiano/pkg/uefi"
	"github.com/linuxboot/fiano/pkg/visitors"
)

var (
	host    = flag.String("h", "127.0.0.1", "host")
	port    = flag.String("p", "8080", "port")
	browser = flag.String("b", "", "open URL in the given brower (ex: firefox)")

	logBuffer   = &bytes.Buffer{}
	printBuffer = &bytes.Buffer{}
)

func jsonResponse(w http.ResponseWriter, obj interface{}) {
	w.Header().Add("Content-Type", "application/json")
	out, err := json.MarshalIndent(obj, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	if _, err := w.Write(out); err != nil {
		log.Fatal(err)
	}
}

// HTTP Enpoints:
//
//     GET / - returns HTML
//     GET /list - returns flattend json list of nodes
//     GET /visitors - returns a list of visitors
//     POST /visitors/NAME/ARG0/ARG1/...
//     GET /log
func registerHandlers(root uefi.Firmware) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "bad method", 400)
			return
		}

		f, err := os.Open("index.html")
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		if _, err := io.Copy(w, f); err != nil {
			log.Fatal(err)
		}
	})

	// Endpoint contains json-encoded output of flatten visitor.
	http.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "bad method", 400)
			return
		}

		// Clone via encode/decode to get around the destructive nature of
		// flatten.
		var clone uefi.Firmware
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(&root); err != nil {
			http.Error(w, fmt.Sprintf("error encoding: %v", err), 400)
			return
		}
		if err := gob.NewDecoder(&buf).Decode(&clone); err != nil {
			http.Error(w, fmt.Sprintf("error decoding: %v", err), 400)
			return
		}

		// Flatten the tree otherwise JavaSCript would be unable to tell which
		// objects are uefi.Firmware.
		flatten := visitors.Flatten{}
		if err := flatten.Run(clone); err != nil {
			log.Fatal(err)
		}
		jsonResponse(w, flatten.List)
	})

	http.HandleFunc("/visitors", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "bad method", 400)
			return
		}
		jsonResponse(w, visitors.VisitorRegistry)
	})

	http.HandleFunc("/visitors/", func(w http.ResponseWriter, r *http.Request) {
		// TODO: white list and constrict save directory

		if r.Method != "POST" {
			http.Error(w, "bad method", 400)
			return
		}

		path := []string{}
		for _, p := range strings.Split(r.URL.Path, "/") {
			if p != "" {
				path = append(path, p)
			}
		}
		if len(path) < 2 {
			http.Error(w, "bad path", 400)
			return
		}
		cmd, args := path[1], path[2:]
		entry, ok := visitors.VisitorRegistry[cmd]
		if !ok {
			http.Error(w, "visitor not found", 400)
			return
		}
		if entry.NumArgs != len(args) {
			http.Error(w, "bad number of arguments", 400)
			return
		}
		v, err := entry.CreateVisitor(args)
		if err != nil {
			log.Fatal(err)
		}
		if err := v.Run(root); err != nil {
			log.Fatal(err)
		}
		log.Println("Ran command", cmd, args)
		jsonResponse(w, []struct{}{})
	})

	// Endpoint returns logs which have not yet been read.
	http.HandleFunc("/log", func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(w, logBuffer); err != nil {
			http.Error(w, "error copying logs", 400)
			return
		}
		if _, err := io.Copy(w, printBuffer); err != nil {
			http.Error(w, "error copying logs", 400)
			return
		}
	})
}

func main() {
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatal("TODO usage")
	}

	// Load and parse the image.
	// TODO: dedup with pkg/utk
	path := flag.Arg(0)
	f, err := os.Stat(path)
	if err != nil {
		log.Fatal(err)
	}
	var root uefi.Firmware
	if m := f.Mode(); m.IsDir() {
		// Call ParseDir
		pd := visitors.ParseDir{BasePath: path}
		if root, err = pd.Parse(); err != nil {
			log.Fatal(err)
		}
		// Assemble the tree from the bottom up
		a := visitors.Assemble{}
		if err = a.Run(root); err != nil {
			log.Fatal(err)
		}
	} else {
		// Regular file
		image, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		root, err = uefi.Parse(image)
		if err != nil {
			log.Fatal(err)
		}
	}

	registerHandlers(root)

	address := *host + ":" + *port
	l, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal("cannot listen on %q: %v", address, err)
	}

	if *browser != "" {
		go func() {
			err := exec.Command(*browser, address).Run()
			if err != nil {
				log.Printf("Failed to open browser: %v", err)
			}
			fmt.Printf("Open http://%s in your web browser", address)
		}()
	} else {
		fmt.Printf("Open http://%s in your web browser", address)
	}

	visitors.Stdout = printBuffer
	log.SetOutput(logBuffer) // TODO: tee to stdout
	log.Print("Welcome to iUTK!")
	log.Fatal(http.Serve(l, nil))
}
