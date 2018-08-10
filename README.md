# fiano

Go-based tools for modifying UEFI firmware.

## Available tools

* [utk](utk/): generic UEFI tool kit meant to handle rom images. Usage:
  + `utk parse <rom-file>`
  + `utk extract [--force] <rom-file> <directory-to-extract-to>`
  + `utk assemble <directory-to-extract-to> <out-rom-file>`
+ [fmap](fmap/): parses flash maps. Usage:
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
    go get github.com/linuxboot/fiano/utk

    # For fmap:
    go get github.com/linuxboot/fiano/fmap
