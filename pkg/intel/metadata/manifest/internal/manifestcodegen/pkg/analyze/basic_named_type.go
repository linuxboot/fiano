package analyze

import (
	"fmt"

	"github.com/xaionaro-go/gosrc"
)

// BasicNamedType exports the structure BasiNamedType.
type BasicNamedType struct {
	gosrc.AstTypeSpec
	Parent *File
}

// PrettyString returns the instance of BasicNamedType as formatted string.
func (t BasicNamedType) PrettyString() (string, error) {
	result, err := getPrettyString(t.TypeSpec.Name, t.TypeSpec.Doc, t.TypeSpec.Comment, "PrettyString:")
	if err != nil {
		err = fmt.Errorf("unable to get PrettyString for '%s'", t.TypeSpec.Name.Name)
	}
	return result, err
}

// Methods returns the functions of the BasicNamedType instance
func (t BasicNamedType) Methods() Funcs {
	var result Funcs
	for _, method := range t.AstTypeSpec.Methods() {
		result = append(result, &Func{
			Parent: t.Parent,
			Func:   *method,
		})
	}
	return result
}
