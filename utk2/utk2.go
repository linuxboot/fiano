package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/linuxboot/fiano/uefi"
	"github.com/linuxboot/fiano/visitors"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("at least one argument is required")
	}

	v, err := visitors.ParseCLI(os.Args[2:])
	if err != nil {
		log.Fatal(err)
	}

	// Load and parse the image.
	// TODO: if os.Args[1] is a directory, re-assemble it
	image, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	parsedRoot, err := uefi.Parse(image)
	if err != nil {
		log.Fatal(err)
	}

	// Execute the instructions from the command line.
	if err := visitors.ExecuteCLI(parsedRoot, v); err != nil {
		log.Fatal(err)
	}
}
