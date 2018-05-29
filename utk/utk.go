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

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	subcommands.Register(&parseCmd{}, "")
	flag.Parse()

	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
