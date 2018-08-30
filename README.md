# fiano

Go-based tools for modifying UEFI firmware.

[![CircleCI](https://circleci.com/gh/linuxboot/fiano.svg?style=shield)](https://circleci.com/gh/linuxboot/fiano)
[![Build Status](https://travis-ci.com/linuxboot/fiano.png)](https://travis-ci.com/linuxboot/fiano/)
[![Go Report
Card](https://goreportcard.com/badge/github.com/linuxboot/fiano)](https://goreportcard.com/report/github.com/linuxboot/fiano)
[![GoDoc](https://godoc.org/github.com/linuxboot/fiano?status.svg)](https://godoc.org/github.com/linuxboot/fiano)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://github.com/linuxboot/fiano/blob/master/LICENSE)

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
