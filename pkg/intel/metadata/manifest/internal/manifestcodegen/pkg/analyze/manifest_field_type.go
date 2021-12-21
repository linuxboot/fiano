package analyze

import (
	"fmt"
)

// ManifestFieldType represents the custom type
type ManifestFieldType uint

const (
	// ManifestFieldTypeUndefined indicates that the field is undefined
	ManifestFieldTypeUndefined = ManifestFieldType(iota)
	// ManifestFieldTypeElement indicates that the field is an element
	ManifestFieldTypeElement
	// ManifestFieldTypeElementList indicates that the field is a list of elements
	ManifestFieldTypeElementList
	// ManifestFieldTypeStructInfo indicates that the field is a StructInfo
	ManifestFieldTypeStructInfo
	// ManifestFieldTypeSubStruct indicates that the field is a underlaying struct
	ManifestFieldTypeSubStruct
	// ManifestFieldTypeEndValue indicates that the field is an EndValue
	ManifestFieldTypeEndValue
	// ManifestFieldTypeByteArrayDynamic indicates that the field is a´ dynamic byte array
	ManifestFieldTypeByteArrayDynamic
	// ManifestFieldTypeByteArrayStatic indicates that the field is a static byte array
	ManifestFieldTypeByteArrayStatic
	// ManifestFieldTypeList indicates that the field is a type list
	ManifestFieldTypeList
)

func (ft ManifestFieldType) String() string {
	switch ft {
	case ManifestFieldTypeUndefined:
		return "undefined"
	case ManifestFieldTypeElement:
		return "element"
	case ManifestFieldTypeElementList:
		return "elementList"
	case ManifestFieldTypeStructInfo:
		return "structInfo"
	case ManifestFieldTypeSubStruct:
		return "subStruct"
	case ManifestFieldTypeEndValue:
		return "endValue"
	case ManifestFieldTypeByteArrayDynamic:
		return "arrayDynamic"
	case ManifestFieldTypeByteArrayStatic:
		return "arrayStatic"
	case ManifestFieldTypeList:
		return "list"
	}
	return fmt.Sprintf("unexpected_%d", uint(ft))
}
