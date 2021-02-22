package analyze

import (
	"fmt"

	"github.com/xaionaro-go/gosrc"
)

type Struct struct {
	gosrc.Struct

	Parent *File
	Fields []*Field
}

func (_struct Struct) ElementStructInfoField() *Field {
	for _, field := range _struct.Fields {
		if field.isElementStructInfo() {
			return field
		}
	}

	return nil
}

func (_struct Struct) ElementStructVersion() string {
	field := _struct.ElementStructInfoField()
	if field == nil {
		return ""
	}

	id, _ := field.TagGet("version")
	return id
}

func (_struct Struct) ElementStructID() string {
	field := _struct.ElementStructInfoField()
	if field == nil {
		return ""
	}

	id, _ := field.TagGet("id")
	return id
}

func (_struct Struct) IsElementsContainer() bool {
	for _, field := range _struct.Fields {
		if field.IsElement() {
			return true
		}
	}

	return false
}

func (_struct Struct) PrettyString() (string, error) {
	result, err := getPrettyString(_struct.TypeSpec.Name, _struct.TypeSpec.Doc, _struct.TypeSpec.Comment, "PrettyString:")
	if err != nil {
		err = fmt.Errorf("unable to get PrettyString for '%s'", _struct.TypeSpec.Name.Name)
	}
	return result, err
}

func (_struct Struct) Methods() Funcs {
	var result Funcs
	for _, method := range _struct.AstTypeSpec.Methods() {
		result = append(result, &Func{Func: *method})
	}
	return result
}

func (_struct Struct) HasOnRehash() bool {
	return _struct.MethodByName("onRehash") != nil
}

func (_struct Struct) ElementStructInfoVar0() string {
	f := _struct.ElementStructInfoField()
	if f == nil {
		return ""
	}
	r, _ := f.TagGet("var0")
	return r
}

func (_struct Struct) ElementStructInfoVar1() string {
	f := _struct.ElementStructInfoField()
	if f == nil {
		return ""
	}
	r, _ := f.TagGet("var1")
	return r
}
