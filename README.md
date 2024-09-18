# fiano

Go-based tools for modifying UEFI firmware.

[![CircleCI](https://circleci.com/gh/linuxboot/fiano.svg?style=shield)](https://circleci.com/gh/linuxboot/fiano)
[![Go Report
Card](https://goreportcard.com/badge/github.com/linuxboot/fiano)](https://goreportcard.com/report/github.com/linuxboot/fiano)
[![GoDoc](https://godoc.org/github.com/linuxboot/fiano?status.svg)](https://godoc.org/github.com/linuxboot/fiano)
[![CodeCov](https://codecov.io/gh/linuxboot/fiano/branch/master/graph/badge.svg)](https://codecov.io/gh/linuxboot/fiano/)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://github.com/linuxboot/fiano/blob/master/LICENSE)

![Fiano](./fiano-logo.svg)

# Contributing

For information about contributing, including how we sign off commits, please see
CONTRIBUTING.md

## UTK: Generic UEFI tool kit meant to handle rom images

Example usage:

```
# For a comprehensive list of commands
utk -h

# Display the image in a compact table form:
utk winterfell.rom table

# Summarize everything in JSON:
utk winterfell.rom json

# List information about a single file in JSON (using regex):
utk winterfell.rom find Shell

# Dump an EFI file to an ffs
utk winterfell.rom dump DxeCore dxecore.ffs

# Insert an EFI file into an FV near another Dxe
utk winterfell.rom insert_before Shell dxecore.ffs save inserted.rom
utk winterfell.rom insert_after Shell dxecore.ffs save inserted.rom

# Insert an EFI file into an FV at the front or the end
# "Shell" is just a means of specifying the FV that contains Shell
utk winterfell.rom insert_front Shell dxecore.ffs save inserted.rom
utk winterfell.rom insert_end Shell dxecore.ffs save inserted.rom

# Remove a file and pad the firmware volume to maintain offsets for the following files
utk winterfell.rom remove_pad Shell save removed.rom

# Remove two files by their GUID without padding and replace shell with Linux:
utk winterfell.rom \
  remove 12345678-9abc-def0-1234-567890abcdef \
  remove 23830293-3029-3823-0922-328328330939 \
  replace_pe32 Shell linux.efi \
  save winterfell2.rom

# Extract everything into a directory:
utk winterfell.rom extract winterfell/

# Re-assemble the directory into an image:
utk winterfell/ save winterfell2.rom
```

### DXE Cleaner

Delete unnecessary DXEs from your firmware. Free up space, speed up boot times
and decrease the attack surface area! See the demo:

[![asciicast](https://asciinema.org/a/233950.svg)](https://asciinema.org/a/233950)

## FMAP: Parses flash maps.

Example usage:

  + `fmap checksum [md5|sha1|sha256] FILE`
  + `fmap extract i FILE`
  + `fmap jget JSONFILE FILE`
  + `fmap jput JSONFILE FILE`
  + `fmap summary FILE`
  + `fmap usage FILE`
  + `fmap verify FILE`

## Installation

    # Golang version 1.13 is required:
    go version

    # For UTK:
    go install github.com/linuxboot/fiano/cmds/utk@latest

    # For fmap:
    go install github.com/linuxboot/fiano/cmds/fmap@latest

The executables are installed in `$HOME/go/bin`.

## Updating Dependencies

    # Fiano utilizes Go modules.
    Use the following to download the dependencies:
    ```
    go mod download
    go mod verify
    ```

    If you desire to update a existing dependency to a newer version:
    ```
    go get path/to/dependency/module@tag
    ```
    Execute this in any directory of fiano repository
