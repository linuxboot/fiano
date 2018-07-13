package uefi

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
)

// Firmware is an interface to describe generic firmware types. The
// implementations (e.g. Flash image, or FirmwareVolume) must implement this
// interface.
type Firmware interface {
	Validate() []error
	Extract(dirpath string) error
	Assemble() ([]byte, error)
}

// This should never be exposed, it is only used for marshalling different types to json.
type marshalFirmware struct {
	FType           string
	FirmwareElement json.RawMessage
}

var firmwareTypes = map[string]Firmware{}

func init() {
	firmwareTypes["*uefi.FlashImage"] = new(FlashImage)
	firmwareTypes["*uefi.BIOSRegion"] = new(BIOSRegion)
}

// MarshalFirmware marshals the firmware element to JSON, including the type information at the top.
func MarshalFirmware(f Firmware) ([]byte, error) {
	b, err := json.MarshalIndent(f, "", "    ")
	if err != nil {
		return nil, err
	}

	m := marshalFirmware{FType: reflect.TypeOf(f).String(), FirmwareElement: json.RawMessage(b)}
	return json.MarshalIndent(m, "", "    ")
}

// UnmarshalFirmware unmarshals the firmware element from JSON, using the type information at the top.
func UnmarshalFirmware(b []byte) (Firmware, error) {
	var m marshalFirmware
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	f, ok := firmwareTypes[m.FType]
	if !ok {
		return nil, fmt.Errorf("unknown Firmware type %s, unable to unmarshal", m.FType)
	}
	err := json.Unmarshal(m.FirmwareElement, &f)
	return f, err
}

// Parse exposes a high-level parser for generic firmware types. It does not
// implement any parser itself, but it calls known parsers that implement the
// Firmware interface.
func Parse(buf []byte) (Firmware, error) {
	if _, err := FindSignature(buf); err == nil {
		// Intel rom.
		return NewFlashImage(buf)
	}
	// Non intel image such as edk2's OVMF
	// We don't know how to parse this header, so treat it as a large BIOSRegion
	return NewBIOSRegion(buf, nil)
}

// ExtractBinary simply dumps the binary to a specified directory and filename.
// It creates the directory if it doesn't already exist, and dumps the buffer to it.
// It returns the filepath of the binary, and an error if it exists.
// This is meant as a helper function for other Extract functions.
func ExtractBinary(buf []byte, dirPath string, filename string) (string, error) {
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return "", err
	}

	// Dump the binary.
	fp := filepath.Join(dirPath, filename)
	if err := ioutil.WriteFile(fp, buf, 0666); err != nil {
		// Make sure we return "" since we don't want an invalid path to be serialized out.
		return "", err
	}
	return fp, nil
}

// Checksum8 does a 8 bit checksum of the slice passed in.
func Checksum8(buf []byte) uint8 {
	var sum uint8
	for _, val := range buf {
		sum += val
	}
	return sum
}

// Checksum16 does a 16 bit checksum of the byte slice passed in.
func Checksum16(buf []byte) (uint16, error) {
	r := bytes.NewReader(buf)
	buflen := len(buf)
	if buflen%2 != 0 {
		return 0, fmt.Errorf("byte slice does not have even length, not able to do 16 bit checksum. Length was %v",
			buflen)
	}
	var temp, sum uint16
	for i := 0; i < buflen; i += 2 {
		if err := binary.Read(r, binary.LittleEndian, &temp); err != nil {
			return 0, err
		}
		sum += temp
	}
	return sum, nil
}

// Read3Size reads a 3-byte size and returns it as a uint64
func Read3Size(size [3]uint8) uint64 {
	return uint64(size[2])<<16 |
		uint64(size[1])<<8 | uint64(size[0])
}

func align(val uint64, base uint64) uint64 {
	return (val + base - 1) & ^(base - 1)
}

// Align4 aligns an address to 4 bytes
func Align4(val uint64) uint64 {
	return align(val, 4)
}

// Align8 aligns an address to 8 bytes
func Align8(val uint64) uint64 {
	return align(val, 8)
}
