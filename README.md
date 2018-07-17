# fiano
reworked EDK2 tools and code we need in a form the open source community is used to

## Available tools

* [utk](utk/): generic UEFI tool kit meant to handle rom images. Usage:
  + `utk parse <rom-file>`
  + `utk extract [--force] <rom-file> <directory-to-extract-to>`
  + `utk assemble <directory-to-extract-to> <out-rom-file>`
