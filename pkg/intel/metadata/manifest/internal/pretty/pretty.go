package pretty

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/dustin/go-humanize"
)

func Header(depth uint, description string, obj interface{}) string {
	if description == "" {
		description = fmt.Sprintf("%T", obj)
	}
	switch depth {
	case 0:
		description = `----` + description + "----\n"
	case 1:
		description = `--` + description + `--`
	default:
		description += `:`
	}
	description = strings.Repeat("  ", int(depth)) + description
	return description
}

func SubValue(depth uint, fieldName, valueDescription string, value interface{}) string {
	if valueDescription == "" {
		valueDescription = getDescriptionForValue(depth, value)
	}
	return fmt.Sprintf("%s %s", Header(depth, fieldName, nil), valueDescription)
}

func getDescriptionForValue(depth uint, value interface{}) string {
	v := reflect.ValueOf(value)
	if v.Kind() == reflect.Ptr && v.IsNil() {
		return "is not set (nil)"
	}

	switch value := value.(type) {
	case interface {
		PrettyString(depth uint, withHeader bool) string
	}:
		description := value.PrettyString(depth, false)
		if len(strings.Split(description, "\n")) > 1 {
			return "\n" + description
		} else {
			return strings.TrimSpace(description)
		}
	case fmt.GoStringer:
		return value.GoString()
	case fmt.Stringer:
		return value.String()
	}

	v = reflect.Indirect(v)
	switch v.Kind() {
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		i := v.Uint()
		var hexFmt string
		switch v.Type().Size() {
		case 1:
			hexFmt = "0x%02X"
		case 2:
			hexFmt = "0x%04X"
		case 4:
			hexFmt = "0x%08X"
		case 8:
			hexFmt = "0x%16X"
		}
		switch {
		case i < 10:
			return fmt.Sprintf(hexFmt, i)
		case i < 65536:
			return fmt.Sprintf(hexFmt+" (%d)", i, i)
		default:
			return fmt.Sprintf(hexFmt+" (%d: %s)", i, i, humanize.IBytes(i))
		}

	case reflect.Array:
		return fmt.Sprintf("0x%X", v.Interface())

	case reflect.Slice:
		if v.Len() == 0 {
			return "empty (len: 0)"
		}
		return fmt.Sprintf("0x%X (len: %d)", v.Interface(), v.Len())
	}

	return fmt.Sprintf("%#+v (%T)", value, value)
}
