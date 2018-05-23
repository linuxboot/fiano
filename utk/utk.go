package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/linuxboot/fiano/uefi"
)

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		log.Fatal("A file name is required")
	}
	romfile := flag.Args()[0]
	buf, err := ioutil.ReadFile(romfile)
	if err != nil {
		log.Fatal(err)
	}
	flash, err := uefi.Parse(buf)
	if err != nil {
		log.Fatal(err)
	}
	errlist := flash.Validate()
	for _, err := range errlist {
		fmt.Printf("Error found: %v\n", err.Error())
	}
	if len(errlist) > 0 {
		os.Exit(1)
	}
	fmt.Println(flash.Summary())
}
