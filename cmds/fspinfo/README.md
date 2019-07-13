## fspinfo

`fspinfo` is a library and command line to parse and present [FSP](https://github.com/IntelFsp/FSP/blob/master/FSP_License.pdf)
information.

Intel FSP specification 2.0 can be found at
https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/fsp-architecture-spec-v2.pdf
.

## Example

Grab an FSP file at https://github.com/IntelFsp/FSP if you don't have one already.

NOTE: currently only the FSP 2.0 specification is supported, make sure to use
the right file (e.g. the ApolloLake one).

```
$ go run github.com/linuxboot/fiano/cmds/fspinfo/ FSP/ApolloLakeFspBinPkg/FspBin/Fsp.fd
Signature                   : FSPH
Header Length               : 72
Reserved1                   : 0x0000
Spec Version                : 2.0
Header Revision             : 3
Image Revision              : 1.4.3.1
Image ID                    : $APLFSP$
Image Size                  : 0x0002a000 172032
Image Base                  : 0x00200000 2097152
Image Attribute             : 0x01 GraphicsDisplaySupported
Component Attribute         : 0x3003 ReleaseBuild|TestRelease|TypeFSP-S (reserved bits are not zeroed)
Cfg Region Offset           : 0x00000124 292
Cfg Region Size             : 0x000003b0 944
Reserved2                   : 0x00000000
TempRAMInit Entry Offset    : 0x00000000 0
Reserved3                   : 0x00000000
NotifyPhase Entry Offset    : 0x00000580 1408
FSPMemoryInit Entry Offset  : 0x00000000 0
TempRAMExit Entry Offset    : 0x00000000 0
FSPSiliconInit Entry Offset : 0x0000058a 1418
```

You can also specify `-j` to obtain JSON output instead.

## Limitations

* Only the FSP 2.0 specification is currently implemented. Previous versions are
  not supported yet.
* The `FSP_INFO_EXTENDED_HEADER` is not implemented yet.
