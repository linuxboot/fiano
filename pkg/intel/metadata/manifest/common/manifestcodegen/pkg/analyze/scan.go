// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package analyze

import (
	"fmt"
	"go/ast"
	"go/build"
	"path/filepath"
	"strings"

	"github.com/xaionaro-go/gosrc"
)

// Scan holds information about a scan process used to scan a path.
func Scan(
	path string,
	goPaths []string,
) (*Package, error) {

	// Scan the path "path".
	pkgRaw, err := getRawPkg(path, goPaths)
	if err != nil {
		return nil, fmt.Errorf("unable to get the package from directory '%s': %w", path, err)
	}

	// Basically just converting received structures to our-own types,
	// which we will used then in cmd/manifestcodegen/template_methods.go.
	pkg, err := convertRawPkg(pkgRaw)
	if err != nil {
		return nil, fmt.Errorf("unable to get convert the package: %w", err)
	}

	return pkg, nil
}

func getRawPkg(
	path string,
	goPaths []string,
) (*gosrc.Package, error) {
	buildCtx := build.Default
	buildCtx.GOPATH = strings.Join(goPaths, string(filepath.ListSeparator))
	buildCtx.BuildTags = append(buildCtx.BuildTags, `manifestcodegen`)
	dirRaw, err := gosrc.OpenDirectoryByPkgPath(&buildCtx, path, false, false, false, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to open go directory: %w", err)
	}

	if len(dirRaw.Packages) != 1 {
		return nil, fmt.Errorf("expected one package in the directory, but received %d", len(dirRaw.Packages))
	}

	return dirRaw.Packages[0], nil
}

func convertRawPkg(
	pkgRaw *gosrc.Package,
) (*Package, error) {
	pkg := &Package{
		Package: *pkgRaw,
	}
	for _, fileRaw := range pkgRaw.Files.FilterByGoGenerateTag("manifestcodegen") {
		file := &File{
			File:            *fileRaw,
			Parent:          pkg,
			Structs:         map[string]*Struct{},
			BasicNamedTypes: map[string]*BasicNamedType{},
		}

		for _, astTypeSpec := range fileRaw.AstTypeSpecs() {
			switch astTypeSpec.TypeSpec.Type.(type) {
			case *ast.StructType:
				structRaw := &gosrc.Struct{AstTypeSpec: *astTypeSpec}
				fieldsRaw, err := structRaw.Fields()
				if err != nil {
					return nil, fmt.Errorf("unable to get fields of struct '%s': %w", structRaw, err)
				}

				_struct := &Struct{
					Struct: *structRaw,
					Parent: file,
				}
				for _, fieldRaw := range fieldsRaw {
					_struct.Fields = append(_struct.Fields, &Field{
						Field:  *fieldRaw,
						Parent: _struct,
					})
				}

				if _struct := pkg.StructByName(_struct.Name()); _struct != nil {
					return nil, fmt.Errorf("structure %s is defined twice (files: '%s' and '%s')", _struct.Name(), _struct.Parent.File, file.Path)
				}
				file.Structs[_struct.Name()] = _struct

			case *ast.Ident:
				file.BasicNamedTypes[astTypeSpec.TypeSpec.Name.Name] = &BasicNamedType{
					Parent:      file,
					AstTypeSpec: *astTypeSpec,
				}
			}
		}

		pkg.Files = append(pkg.Files, file)
	}

	return pkg, nil
}
