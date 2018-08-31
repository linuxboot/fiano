# fiano

Go-based tools for modifying UEFI firmware.

[![CircleCI](https://circleci.com/gh/linuxboot/fiano.svg?style=shield)](https://circleci.com/gh/linuxboot/fiano)
[![Build Status](https://travis-ci.com/linuxboot/fiano.png)](https://travis-ci.com/linuxboot/fiano/)
[![Go Report
Card](https://goreportcard.com/badge/github.com/linuxboot/fiano)](https://goreportcard.com/report/github.com/linuxboot/fiano)
[![GoDoc](https://godoc.org/github.com/linuxboot/fiano?status.svg)](https://godoc.org/github.com/linuxboot/fiano)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://github.com/linuxboot/fiano/blob/master/LICENSE)

## UTK: Generic UEFI tool kit meant to handle rom images

Example usage:

```
# Dump everything to JSON:
utk winterfell.rom json

# Dump a single file to JSON (using regex):
utk winterfell.rom find Shell

# Dump GUIDs and sizes to a compact table:
utk winterfell.rom table

# Extract everything into a directory:
utk winterfell.rom extract winterfell/

# Re-assemble the directory into an image:
utk winterfell/ save winterfell2.rom

# Remove two files by their GUID and replace shell with Linux:
utk winterfell.rom \
  remove 12345678-9abc-def0-1234-567890abcdef \
  remove 23830293-3029-3823-0922-328328330939 \
  replace_pe32 Shell linux.efi \
  save winterfell2.rom
```

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

    # Golang version 1.10 is required
    go version

    # For UTK:
    go get github.com/linuxboot/fiano/cmds/utk

    # For fmap:
    go get github.com/linuxboot/fiano/cmds/fmap
