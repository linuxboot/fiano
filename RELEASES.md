# Releases

A new release happens every 6 weeks:

- 1st day on the first month of each quarter
- 15th day of the second month of each quarter

## v2.0.0 (2018-10-01)

- utk2 has been merged into utk and the visitor pattern is here to stay.
- New major features:
  - Support for assembling compressed subsections
  - Improved test coverage
  - Support for CircleCI
  - Support for dependency expression parsing
- New visitors:
  - assemble, cat, count, dump, extract, find, insert, remove, table, verify
- Major bug fixes:
  - Fixed losing padding data between firmware volumes.
  - Fixed growing a compressed firmware volume to the excess of 16MiB.
  - Pads files are now created appropriately and without conflicting GUIDs.
- Tested with:
  - Golang 1.11
  - u-root v2.0.0

## v1.0.0 (2018-08-15)

- Initial release
- Tested with:
  - Golang 1.10.3
  - u-root v1.0.0
- Known bugs:
  - [#67](https://github.com/linuxboot/fiano/issues): UTK incorrectly loses pad
  files when multiple pad files contain the same GUID. It is common for BIOSes
  to set the GUID of all pad files to FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF.
