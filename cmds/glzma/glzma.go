package main

import (
	"flag"
	"io/ioutil"
	"log"

	"github.com/linuxboot/fiano/pkg/lzma"
)

var (
	d   = flag.Bool("d", false, "decode")
	e   = flag.Bool("e", false, "encode")
	f86 = flag.Bool("f86", false, "use x86 extension")
	o   = flag.String("o", "", "output file")
)

func main() {
	flag.Parse()

	if *d == *e {
		log.Fatal("either decode (-d) or encode (-e) must be set")
	}
	if *o == "" {
		log.Fatal("output file must be set")
	}
	if flag.NArg() != 1 {
		log.Fatal("expected one input file")
	}

	var op func([]byte) ([]byte, error)
	switch {
	case *d && !*f86:
		op = lzma.Decode
	case *d && *f86:
		op = lzma.DecodeX86
	case *e && !*f86:
		op = lzma.Encode
	case *e && *f86:
		op = lzma.EncodeX86
	}

	in, err := ioutil.ReadFile(flag.Args()[0])
	if err != nil {
		log.Fatal(err)
	}
	out, err := op(in)
	if err != nil {
		log.Fatal(err)
	}
	if err := ioutil.WriteFile(*o, out, 0666); err != nil {
		log.Fatal(err)
	}
}
