// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package analyze

import (
	"github.com/xaionaro-go/gosrc"
)

// File struct has four fields. gosrc.File holds the associated file.
// Parent represents the package as element containing the file.
// Structs holds a map of all structures of a file matching to their name in string representation.
// BasicNamedTypes holds
type File struct {
	gosrc.File

	Parent          *Package
	Structs         map[string]*Struct
	BasicNamedTypes map[string]*BasicNamedType
}

// Package contains zwo fields. gosrc.Package and an slice of file pointers.
type Package struct {
	gosrc.Package

	Files []*File
}

// StructByName returns Struct with the given name.
func (pkg *Package) StructByName(structName string) *Struct {
	for _, file := range pkg.Files {
		if _struct, ok := file.Structs[structName]; ok {
			return _struct
		}
	}

	return nil
}

// Structs returns a map matching StructNames to pointers of their struct instance.
func (pkg *Package) Structs() map[string]*Struct {
	result := map[string]*Struct{}
	for _, file := range pkg.Files {
		for structName, _struct := range file.Structs {
			result[structName] = _struct
		}
	}
	return result
}
