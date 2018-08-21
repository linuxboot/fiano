package visitors

import (
	"io/ioutil"
	"os"

	"github.com/linuxboot/fiano/uefi"
)

// Extract prints any Firmware node as Extract.
// TODO: it would be better to make the Extract interface method a visitor
// itself.
type Extract struct {
	DirPath string
}

// Visit applies the Extract visitor to any Firmware type.
func (v *Extract) Visit(f uefi.Firmware) error {
	// Create the directory if it does not exist.
	if err := os.MkdirAll(v.DirPath, 0755); err != nil {
		return err
	}

	// Change working directory so we can use relative paths.
	// TODO: commands after this in the pipeline are in unexpected directory
	if err := os.Chdir(v.DirPath); err != nil {
		return err
	}

	f.Extract(".")

	// Output summary json.
	json, err := uefi.MarshalFirmware(f)
	if err != nil {
		return err
	}
	return ioutil.WriteFile("summary.json", json, 0666)
}

func init() {
	RegisterCLI("extract", 1, func(args []string) (uefi.Visitor, error) {
		return &Extract{
			DirPath: args[0],
		}, nil
	})
}
