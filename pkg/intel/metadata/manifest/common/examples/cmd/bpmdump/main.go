package main

import (
	"fmt"
	"log"
	"os"

	"github.com/linuxboot/fiano/pkg/intel/metadata/manifest/bootpolicy"
)

func assertNoError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	f, err := os.Open(os.Args[1])
	assertNoError(err)

	m := &bootpolicy.Manifest{}
	_, err = m.ReadFrom(f)
	assertNoError(err)

	fmt.Printf("%s", m.PrettyString(0, true))
}
