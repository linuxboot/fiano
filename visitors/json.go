package visitors

import (
	"encoding/json"
	"fmt"

	"github.com/linuxboot/fiano/uefi"
)

// JSON prints any Firmware node as JSON.
type JSON struct{}

// Visit applies the JSON visitor to any Firmware type.
func (v *JSON) Visit(f uefi.Firmware) error {
	b, err := json.MarshalIndent(f, "", "\t")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func init() {
	RegisterCLI("json", 0, func(args []string) (uefi.Visitor, error) {
		return &JSON{}, nil
	})
}
