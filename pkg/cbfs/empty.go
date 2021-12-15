package cbfs

import (
	"io"
	"log"
)

func init() {
	if err := RegisterFileReader(&SegReader{Type: TypeDeleted, Name: "CBFSEmpty", New: NewEmptyRecord}); err != nil {
		log.Fatal(err)
	}
	if err := RegisterFileReader(&SegReader{Type: TypeDeleted2, Name: "CBFSEmpty", New: NewEmptyRecord}); err != nil {
		log.Fatal(err)
	}
}

func NewEmptyRecord(f *File) (ReadWriter, error) {
	r := &EmptyRecord{File: *f}
	Debug("Got header %v", r.String())
	r.Type = TypeDeleted2
	r.Attr = make([]byte, 16)
	r.FData = ffbyte(f.Size)
	return r, nil
}

func (r *EmptyRecord) Read(in io.ReadSeeker) error {
	return nil
}

func (r *EmptyRecord) String() string {
	return recString("(empty)", r.RecordStart, r.Type.String(), r.Size, "none")
}

func (r *EmptyRecord) Write(w io.Writer) error {
	return Write(w, r.FData)
}

func (r *EmptyRecord) GetFile() *File {
	return &r.File
}
