// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// DXECleaner removes DXEs sequentially in multiple rounds. Each round, an
// attempt is made to remove each DXE. The Test function determines if the
// removal was successful. Additional rounds are performed until all DXEs are
// removed.
type DXECleaner struct {
	// This function tests whether the firmware boots. The return values can be:
	//
	//     - (false, nil): The firmware was tested and failed to boot.
	//     - (false, err): The firmware was tested and failed to boot due to err.
	//     - (true, nil):  The firmware was tested and booted.
	//     - (true, err):  Failed to test the firmware due to err.
	Test func(f uefi.Firmware) (bool, error)

	// Predicate to determine whether a DXE can be removed.
	Predicate FindPredicate

	// List of GUIDs which were removed.
	Removals []guid.GUID

	// Logs are written to this writer.
	W io.Writer
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *DXECleaner) Run(f uefi.Firmware) error {
	var printf = func(format string, a ...interface{}) {
		if v.W != nil {
			fmt.Fprintf(v.W, format, a...)
		}
	}

	// Find list of DXEs.
	find := (&Find{Predicate: v.Predicate})
	if err := find.Run(f); err != nil {
		return err
	}
	var dxes []guid.GUID
	for i := range find.Matches {
		dxes = append(dxes, find.Matches[i].(*uefi.File).Header.GUID)
	}
	if len(dxes) == 0 {
		return errors.New("found no DXEs in firmware image")
	}

	// Print list of removals in a format which can be passed back into UTK.
	defer func() {
		printf("Summary of removed DXEs:\n")
		if len(v.Removals) == 0 {
			printf("  Could not remove any DXEs\n")
		} else {
			for _, r := range v.Removals {
				printf("  remove %s \\\n", r)
			}
		}
	}()

	// Main algorithm to remove DXEs.
	moreRoundsNeeded := true
	for i := 0; moreRoundsNeeded; i++ {
		printf("Beginning of round %d\n", i+1)
		moreRoundsNeeded = false
		for i := 0; i < len(dxes); i++ {
			// Remove the DXE from the image.
			printf("Trying to remove %v\n", dxes[i])
			remove := &Remove{Predicate: FindFileGUIDPredicate(dxes[i])}
			if err := remove.Run(f); err != nil {
				return err
			}

			if removedSuccessfully, err := v.Test(f); err == context.Canceled {
				printf("Canceled by user %v!\n", dxes[i])
				return nil
			} else if removedSuccessfully && err != nil {
				return err
			} else if removedSuccessfully {
				printf("  Success %v!\n", dxes[i])
				v.Removals = append(v.Removals, dxes[i])
				dxes = append(dxes[:i], dxes[i+1:]...)
				i--
				moreRoundsNeeded = true
			} else {
				printf("  Failed %v!\n", dxes[i])
				remove.Undo()
			}
		}
	}
	return nil
}

// Visit applies the DXEClearn visitor to any Firmware type.
func (v *DXECleaner) Visit(f uefi.Firmware) error {
	return nil
}

// readBlackList returns a regex to filter DXEs according to the black list
// file. Each line in the black list is the GUID or name of a firmware file.
// Empty lines and lines beginning with '#' are ignored.
func parseBlackList(fileName, fileContents string) (string, error) {
	blackList := ""
	for _, line := range strings.Split(fileContents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, err := regexp.Compile(line)
		if err != nil {
			return "", fmt.Errorf("cannot compile regex %q from blacklist file %q: %v", line, fileName, err)
		}
		blackList += "|(" + line + ")"
	}
	if blackList != "" {
		blackList = blackList[1:]
	}
	return blackList, nil
}

func init() {
	register := func(args []string) (uefi.Visitor, error) {
		// When the user enters CTRL-C, the DXECleaner should stop, but
		// also output the current progress.
		ctx, cancel := context.WithCancel(context.Background())
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		go func() {
			<-c
			cancel()
		}()

		predicate := FindFileTypePredicate(uefi.FVFileTypeDriver)

		// Create blacklist for DXEs which can be skipped.
		useBlackList := len(args) == 2
		if useBlackList {
			fileName := args[1]
			fileContents, err := ioutil.ReadFile(fileName)
			if err != nil {
				return nil, fmt.Errorf("cannot read blacklist file %q: %v", fileName, err)
			}
			blackListRegex, err := parseBlackList(fileName, string(fileContents))
			if err != nil {
				return nil, err
			}
			if blackListRegex != "" {
				blackListPredicate, err := FindFilePredicate(blackListRegex)
				if err != nil {
					return nil, err
				}
				predicate = FindAndPredicate(predicate, FindNotPredicate(blackListPredicate))
			}
		}

		return &DXECleaner{
			Test: func(f uefi.Firmware) (bool, error) {
				tmpDir, err := ioutil.TempDir("", "dxecleaner")
				if err != nil {
					return true, err
				}
				defer os.RemoveAll(tmpDir)
				tmpFile := filepath.Join(tmpDir, "bios.bin")

				if err := (&Save{tmpFile}).Run(f); err != nil {
					return true, err
				}
				cmd := exec.CommandContext(ctx, args[0], tmpFile)
				cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
				if err := cmd.Run(); err != nil {
					if _, ok := err.(*exec.ExitError); !ok {
						return true, err
					}
					status, ok := err.(*exec.ExitError).Sys().(syscall.WaitStatus)
					if !ok {
						return true, err
					}
					switch status.ExitStatus() {
					case 1:
						return true, err
					case 2:
						return false, err
					default:
						return true, fmt.Errorf("unexpected exit status %d", status.ExitStatus())
					}
				}
				return true, nil
			},
			Predicate: predicate,
			W:         os.Stdout,
		}, nil
	}

	RegisterCLI("dxecleaner", "automates removal of UEFI drivers", 1, register)
	RegisterCLI("dxecleaner_blacklist", "automates removal of UEFI drivers with a blacklist file", 2, register)
}
