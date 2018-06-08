package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/google/subcommands"
	"github.com/linuxboot/fiano/uefi"
)

// Parse subcommand
type parseCmd struct {
}

func (*parseCmd) Name() string {
	return "parse"
}

func (*parseCmd) Synopsis() string {
	return "Parse rom file and print JSON summary to stdout"
}

func (*parseCmd) Usage() string {
	return "parse <path-to-rom-file>\n"
}

func (*parseCmd) SetFlags(_ *flag.FlagSet) {}

func (*parseCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	args := f.Args()
	if len(args) == 0 {
		log.Print("A file name is required")
		return subcommands.ExitUsageError
	}

	romfile := args[0]
	buf, err := ioutil.ReadFile(romfile)
	if err != nil {
		log.Print(err)
		return subcommands.ExitFailure
	}

	flash, err := uefi.Parse(buf)
	if err != nil {
		log.Print(err)
		return subcommands.ExitFailure
	}
	errlist := flash.Validate()
	for _, err := range errlist {
		log.Printf("Error found: %v\n", err.Error())
	}
	if len(errlist) > 0 {
		return subcommands.ExitFailure
	}

	b, err := json.MarshalIndent(flash, "", "    ")
	if err != nil {
		log.Print(err)
		return subcommands.ExitFailure
	}
	fmt.Println(string(b))
	return subcommands.ExitSuccess
}

// Extract subcommand
type extractCmd struct {
}

func (*extractCmd) Name() string {
	return "extract"
}

func (*extractCmd) Synopsis() string {
	return "Extract rom file and print JSON summary to stdout"
}

func (*extractCmd) Usage() string {
	return "extract <path-to-rom-file> <directory-to-extract-into>\n"
}

func (*extractCmd) SetFlags(_ *flag.FlagSet) {}

func (e *extractCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	args := f.Args()
	if len(args) < 2 {
		log.Print(e.Usage())
		return subcommands.ExitUsageError
	}

	romfile := args[0]
	buf, err := ioutil.ReadFile(romfile)
	if err != nil {
		log.Print(err)
		return subcommands.ExitFailure
	}

	flash, err := uefi.Parse(buf)
	if err != nil {
		log.Print(err)
		return subcommands.ExitFailure
	}
	errlist := flash.Validate()
	for _, err := range errlist {
		log.Printf("Error found: %v\n", err.Error())
	}
	if len(errlist) > 0 {
		return subcommands.ExitFailure
	}

	err = flash.Extract(args[1])
	if err != nil {
		log.Print(err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	subcommands.Register(&parseCmd{}, "")
	subcommands.Register(&extractCmd{}, "")
	flag.Parse()

	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
