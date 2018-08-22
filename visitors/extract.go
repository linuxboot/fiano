package visitors

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/linuxboot/fiano/uefi"
)

// Extract prints any Firmware node as Extract.
type Extract struct {
	DirPath string
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Extract) Run(f uefi.Firmware) error {
	// Create the directory if it does not exist.
	if err := os.MkdirAll(v.DirPath, 0755); err != nil {
		return err
	}

	// Change working directory so we can use relative paths.
	// TODO: commands after this in the pipeline are in unexpected directory
	if err := os.Chdir(v.DirPath); err != nil {
		return err
	}

	if err := f.Apply(&Extract{"."}); err != nil {
		return err
	}

	// Output summary json.
	json, err := uefi.MarshalFirmware(f)
	if err != nil {
		return err
	}
	return ioutil.WriteFile("summary.json", json, 0666)
}

// Visit applies the Extract visitor to any Firmware type.
func (v *Extract) Visit(f uefi.Firmware) error {
	// The visior must be cloned before modification; otherwise, the
	// sibling's values are modified.
	v2 := *v

	var err error
	switch f := f.(type) {

	case *uefi.FlashImage:
		f.ExtractPath, err = uefi.ExtractBinary(f.Buf, v2.DirPath, "flash.rom")

	case *uefi.FirmwareVolume:
		v2.DirPath = filepath.Join(v.DirPath, fmt.Sprintf("%#x", f.FVOffset))
		f.ExtractPath, err = uefi.ExtractBinary(f.Buf, v2.DirPath, "fv.bin")

	case *uefi.File:
		// For files we use the GUID as the folder name.
		// TODO: This is a mistake because GUIDs are not unique (pad files especially).
		v2.DirPath = filepath.Join(v.DirPath, f.Header.UUID.String())
		f.ExtractPath, err = uefi.ExtractBinary(f.Buf, v2.DirPath, fmt.Sprintf("%v.ffs", f.Header.UUID))

	case *uefi.Section:
		// For sections we use the file order as the folder name.
		v2.DirPath = filepath.Join(v.DirPath, fmt.Sprint(f.FileOrder))
		f.ExtractPath, err = uefi.ExtractBinary(f.Buf, v2.DirPath, fmt.Sprintf("%v.sec", f.FileOrder))

	case *uefi.FlashDescriptor:
		v2.DirPath = filepath.Join(v.DirPath, "ifd")
		f.ExtractPath, err = uefi.ExtractBinary(f.Buf, v2.DirPath, "flashdescriptor.bin")

	case *uefi.BIOSRegion:
		v2.DirPath = filepath.Join(v.DirPath, "bios")
		f.ExtractPath, err = uefi.ExtractBinary(f.Buf, v2.DirPath, "biosregion.bin")

	case *uefi.GBERegion:
		v2.DirPath = filepath.Join(v.DirPath, "gbe")
		f.ExtractPath, err = uefi.ExtractBinary(f.Buf, v2.DirPath, "gberegion.bin")

	case *uefi.MERegion:
		v2.DirPath = filepath.Join(v.DirPath, "me")
		f.ExtractPath, err = uefi.ExtractBinary(f.Buf, v2.DirPath, "meregion.bin")

	case *uefi.PDRegion:
		v2.DirPath = filepath.Join(v.DirPath, "pd")
		f.ExtractPath, err = uefi.ExtractBinary(f.Buf, v2.DirPath, "pdregion.bin")
	}
	if err != nil {
		return err
	}

	return f.ApplyChildren(&v2)
}

func init() {
	RegisterCLI("extract", 1, func(args []string) (uefi.Visitor, error) {
		return &Extract{
			DirPath: args[0],
		}, nil
	})
}
