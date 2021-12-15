package cbfs

import (
	"io"
	"log"
)

func init() {
	if err := RegisterFileReader(&SegReader{Type: TypeMicroCode, Name: "microcode", New: NewCMOSLayout}); err != nil {
		log.Fatal(err)
	}
}

//NewMicrocode returns a ReadWriter interface for the CBFS type TypeMicroCode
func NewMicrocode(f *File) (ReadWriter, error) {
	rec := &MicrocodeRecord{File: *f}
	return rec, nil
}

func (r *MicrocodeRecord) Read(in io.ReadSeeker) error {
	return nil
}

func (r *MicrocodeRecord) String() string {
	return recString(r.File.Name, r.RecordStart, r.Type.String(), r.Size, "none")
}

func (r *MicrocodeRecord) Write(w io.Writer) error {
	return Write(w, r.FData)
}

//Header returns a pointer to the corresponding File
func (r *MicrocodeRecord) GetFile() *File {
	return &r.File
}
