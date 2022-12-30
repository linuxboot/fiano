// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package analyze

import (
	"fmt"
	"go/ast"

	"github.com/xaionaro-go/gosrc"
)

// Func exports the Func struct
type Func struct {
	Parent *File
	gosrc.Func
}

// Funcs exports the custom type []*Funs
type Funcs []*Func

// ReturnsFlagValue returns bool true if Function has a Flag value
func (fn Func) ReturnsFlagValue() bool {
	if fn.Type.Params != nil && len(fn.Type.Params.List) != 0 {
		return false
	}
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	ident, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	if !ok {
		return false
	}
	if ident.Name == "string" {
		return false
	}
	return true
}

// ReturnsTypeName a string of the TypeName of the function
func (fn Func) ReturnsTypeName() string {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return ""
	}
	ident, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name
}

// PrettyStringForResult returns a string corresponding with the documentation of the implemented function
func (fn Func) PrettyStringForResult(r interface{}) (string, error) {
	result, err := getPrettyString(fn.Type, fn.FuncDecl.Doc, nil, fmt.Sprintf("PrettyString-%v:", r))
	if err != nil {
		err = fmt.Errorf("unable to get PrettyString for '%s'", fn.FuncDecl.Name.Name)
	}
	return result, err
}
