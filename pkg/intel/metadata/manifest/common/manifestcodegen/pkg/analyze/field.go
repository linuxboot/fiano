// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package analyze

import (
	"fmt"
	"go/ast"
	"go/types"
	"math"
	"path/filepath"
	"strings"

	"github.com/xaionaro-go/gosrc"
)

// Field is just a wrapper around gosrc.Field to provide necessary information
// for code generation.
type Field struct {
	gosrc.Field

	Parent *Struct
}

// ItemTypeName returns the type of the given field.
func (field Field) ItemTypeName() string {
	return field.Field.ItemTypeName().Name
}

// AccessPrefix returns a prefix of a given field.
func (field Field) AccessPrefix() string {
	itemTypeName := field.Field.ItemTypeName()
	if itemTypeName.Path == filepath.Dir(field.Parent.Parent.Path) {
		// Not imported, the same package, so no prefix is required
		return ""
	}

	// Imported. As temporary solution we use directory name
	// as the package name.
	return filepath.Base(itemTypeName.Path) + "."
}

// TypeStdSize returns the size (in bytes) of the field's value, if it has
// a static size.
//
// For example if the field has type `uint32` or `[4]byte`, then the returned
// value will be `4`.
//
// Basically this is something like `binary.Size(struct.Field)`.
func (field Field) TypeStdSize() int64 {
	// We set MaxInt64 as wordSize, because we expect wordSize to be
	// never used, so MaxInt64 will help us to reveal any errors.
	//
	// maxAlign is 1 since the data is packed.
	return field.Field.TypeStdSize(math.MaxInt64, 1)
}

// CountType returns the name of the type used to store the count of items
// of the slice. According to document #575623 it is usually uint16, but
// sometimes it is something else (for example uint8).
//
// This method is used only for types ManifestFieldTypeByteArrayDynamic and
// ManifestFieldTypeList.
//
// For example in table 5-11 (of document #575623) there are in particular
// fields `Count and `Digest`, where `Digest` is a list of HASH_STRUCTURE items
// and `Count` is the amount of these items. CountType defines the type of
// the field `Count` in this case (which is `uint16`).
func (field Field) CountType() string {
	if countType, ok := field.TagGet("countType"); ok {
		return countType
	}
	return "uint16"
}

// CountValue returns the value of Tag countValue
func (field Field) CountValue() string {
	result, _ := field.TagGet("countValue")
	return result
}

// RequiredValue returns value of the Tag required
func (field Field) RequiredValue() string {
	result, _ := field.TagGet("require")
	return result
}

// DefaultValue returns the value of the Tag default
func (field Field) DefaultValue() string {
	result, _ := field.TagGet("default")
	return result
}

// PrettyValue returns the value of the Tag prettyValue
func (field Field) PrettyValue() string {
	result, _ := field.TagGet("prettyValue")
	return result
}

// RehashValue returns the value of the tag rehashValue
func (field Field) RehashValue() string {
	result, _ := field.TagGet("rehashValue")
	return result
}

// IsElement returns bool true if a Struct is elements of a field.
func (field Field) IsElement() bool {
	_struct := field.Struct()
	if _struct == nil {
		return false
	}
	info := _struct.ElementStructInfoField()
	return info != nil
}

// IsFlags returns bool true if a field is of type Flags
func (field Field) IsFlags() bool {
	namedType, ok := field.TypeValue.Type.(*types.Named)
	if !ok {
		return false
	}

	return strings.HasSuffix(namedType.Obj().Name(), "Flags")
}

func (field Field) isElementStructInfo() bool {
	return field.Field.ItemTypeName().Name == "StructInfo"
}

// ElementStructID returns the ElementStructID of a Field
func (field Field) ElementStructID() string {
	_struct := field.Struct()
	if _struct == nil {
		return ""
	}
	return _struct.ElementStructID()
}

// Struct returns a pointer to the most upper field structure instance
func (field Field) Struct() *Struct {
	return field.Parent.Parent.Parent.StructByName(field.Field.ItemTypeName().Name)
}

// ManifestFieldType returns the ManifestFieldType of the field instance
func (field Field) ManifestFieldType() (ManifestFieldType, error) {
	_struct := field.Parent
	if _struct == nil {
		return ManifestFieldTypeUndefined, fmt.Errorf("internal error: parent is not defined")
	}

	typ := gosrc.TypeDeepest(field.TypeValue.Type)
	if typCasted, ok := typ.(*types.Pointer); ok {
		typ = typCasted.Elem()
	}
	if typCasted, ok := typ.(*types.Named); ok {
		typ = typCasted.Underlying()
	}

	switch typ := typ.(type) {
	case *types.Array:
		switch typ := typ.Elem().(type) {
		case *types.Basic:
			if typ.Kind() != types.Uint8 {
				return ManifestFieldTypeUndefined, fmt.Errorf("static array, but not of bytes in %s.%s: %s", _struct.Name(), field.Name(), typ.String())
			}
			return ManifestFieldTypeByteArrayStatic, nil
		default:
			return ManifestFieldTypeUndefined, fmt.Errorf("static array, but not of bytes in %s.%s: %s", _struct.Name(), field.Name(), typ.String())
		}
	case *types.Slice:
		switch elemType := typ.Elem().(type) {
		case *types.Basic:
			if elemType.Kind() != types.Uint8 {
				return ManifestFieldTypeUndefined, fmt.Errorf("dynamic array, but not of bytes in %s.%s: %s", _struct.Name(), field.Name(), typ.String())
			}
			return ManifestFieldTypeByteArrayDynamic, nil
		default:
			if field.IsElement() {
				return ManifestFieldTypeElementList, nil
			}
			return ManifestFieldTypeList, nil

		}
	case *types.Struct:
		if field.isElementStructInfo() {
			return ManifestFieldTypeStructInfo, nil
		}
		if field.IsElement() {
			return ManifestFieldTypeElement, nil
		}
		return ManifestFieldTypeSubStruct, nil

	case *types.Basic:
		return ManifestFieldTypeEndValue, nil
	case *types.Interface:
		return ManifestFieldTypeUndefined, fmt.Errorf("do not know how to handle an interface of '%s.%s'", _struct.Name(), field.Name())
	}

	return ManifestFieldTypeUndefined, fmt.Errorf("unknown case: %s:%T: %v", field.Name(), typ, typ.String())
}

// PrettyString returns a formatted string of the field structure instance
func (field Field) PrettyString() (string, error) {
	result, err := getPrettyString(&ast.Ident{Name: field.Name()}, field.Doc, field.Comment, "PrettyString:")
	if err != nil {
		err = fmt.Errorf("unable to get PrettyString for '%s.%s'", field.Parent.TypeSpec.Name.Name, field.Name())
	}
	return result, err
}
