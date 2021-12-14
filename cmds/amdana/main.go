package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	amd "github.com/linuxboot/fiano/pkg/amd/manifest"
)

const (
	// This needed a look at the image; how can we fully automate it?
	mapping = 0xff000000
)

// this is only for Go - would be 5 lines inline in JS, thanks...
type image []byte

func (f image) ImageBytes() []byte {
	return []byte(f)
}

func (f image) PhysAddrToOffset(physAddr uint64) uint64 {
	return physAddr - mapping
}

func (f image) OffsetToPhysAddr(offset uint64) uint64 {
	return offset + mapping
}

func main() {
	flag.Parse()
	args := flag.Args()

	var path string

	if len(args) > 0 {
		path = args[0]
		data, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		// We could also use this, but its mapping wouldn't work with some images
		// FIXME: figure out those mappings
		// var amdfw amd.FirmwareImage = data
		var amdfw image = data
		fw, err := amd.NewAMDFirmware(amdfw)
		if err != nil {
			log.Fatal(err)
		}
		a := fw.PSPFirmware()
		j, err := json.MarshalIndent(a, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf(string(j))
	}
}
