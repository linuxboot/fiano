package cbfs

import (
	"io"
	"log"
)

func init() {
	if err := RegisterFileReader(&SegReader{Type: 2, Name: "CBFSMaster", New: NewMaster}); err != nil {
		log.Fatal(err)
	}
}

func NewMaster(f *File) (ReadWriter, error) {
	r := &MasterRecord{File: *f}
	return r, nil
}

func (r *MasterRecord) Read(in io.ReadSeeker) error {
	if err := Read(in, &r.MasterHeader); err != nil {
		Debug("MasterRecord read: %v", err)
		return err
	}
	Debug("Got header %s offset %#x", r.String(), r.Offset)
	return nil
}

func (r *MasterRecord) String() string {
	return recString(r.File.Name, r.RecordStart, r.Type.String(), r.Size, "none")
}

func (r *MasterRecord) Write(w io.Writer) error {
	return Write(w, r.MasterHeader)
}

func (r *MasterRecord) GetFile() *File {
	return &r.File
}
