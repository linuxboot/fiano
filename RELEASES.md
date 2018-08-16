# Releases

A new release happens every 6 weeks:

- 1st day on the first month of each quarter
- 15th day of the second month of each quarter

## v1.0.0 (2018-08-15)

- Initial release
- Tested with:
  - Golang 1.10.3
  - u-root v1.0.0
- Known bugs:
  - [#67](https://github.com/linuxboot/fiano/issues): UTK incorrectly loses pad
  files when multiple pad files contain the same GUID. It is common for BIOSes
  to set the GUID of all pad files to FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF.
