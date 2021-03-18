package fit

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type EntryTXTPolicyRecordDataInterface interface {
	IsTXTEnabled() bool
}

type EntryTXTPolicyRecordDataIndexedIO struct {
	IndexRegisterIOAddress uint16
	DataRegisterIOAddress  uint16
	AccessWidth            uint8
	BitPosition            uint8
	Index                  uint16
}

func (entryData *EntryTXTPolicyRecordDataIndexedIO) IsTXTEnabled() bool {
	panic("not implemented")
}

type EntryTXTPolicyRecordDataFlatPointer uint64

func (entryData EntryTXTPolicyRecordDataFlatPointer) TPMPolicyPointer() uint64 {
	return uint64(entryData & 0x7fffffffffffffff)
}
func (entryData EntryTXTPolicyRecordDataFlatPointer) IsTXTEnabled() bool {
	return entryData&0x8000000000000000 != 0
}

func (entry *EntryTXTPolicyRecord) Parse() (EntryTXTPolicyRecordDataInterface, error) {
	switch entry.Headers.Version {
	case 0:
		ptr := binary.LittleEndian.Uint64(entry.DataBytes)
		result := EntryTXTPolicyRecordDataFlatPointer(ptr)
		return result, nil
	case 1:
		var dataParsed EntryTXTPolicyRecordDataIndexedIO
		err := binary.Read(bytes.NewReader(entry.DataBytes), binary.LittleEndian, &dataParsed)
		if err != nil {
			return nil, fmt.Errorf("unable to parse EntryTXTPolicyRecordDataIndexedIO: %w", err)
		}
		return &dataParsed, nil
	}

	return nil, &ErrInvalidTXTPolicyRecordVersion{entry.Headers.Version}
}
