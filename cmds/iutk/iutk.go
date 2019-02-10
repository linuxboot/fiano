package main

import (
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/linuxboot/fiano/pkg/uefi"
	"github.com/linuxboot/fiano/pkg/visitors"
)

var (
	host = flag.String("h", "127.0.0.1:8080", "host:port")
)

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
	var parsedRoot uefi.Firmware
	if m := f.Mode(); m.IsDir() {
		// Call ParseDir
		pd := visitors.ParseDir{BasePath: path}
		if parsedRoot, err = pd.Parse(); err != nil {
			log.Fatal(err)
		}
		// Assemble the tree from the bottom up
		a := visitors.Assemble{}
		if err = a.Run(parsedRoot); err != nil {
			log.Fatal(err)
		}
	} else {
		// Regular file
		image, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		parsedRoot, err = uefi.Parse(image)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Load and parse the template.
	tpl, err := ioutil.ReadFile("index.html.template")
	if err != nil {
		log.Fatal(err)
	}
	t, err := template.
		New("webpage").
		Funcs(template.FuncMap{"ToString": visitors.ToString}).
		Parse(string(tpl))
	if err != nil {
		log.Fatal(err)
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		flatten := visitors.Flatten{}
		if err := flatten.Run(parsedRoot); err != nil {
			log.Fatal(err)
		}

		vars := struct {
			Title string
			List  []visitors.FlattenedFirmware
		}{
			Title: flag.Arg(0),
			List:  flatten.List,
		}
		err := t.Execute(w, vars)
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Printf("Open http://%s in your web browser", *host)
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
