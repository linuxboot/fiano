package uefi

// This package implements the mixed-endian UUID as implemented by Microsoft.

import (
	"encoding/hex"
	"errors"
)

var ErrInvalidUUID = errors.New("Invalid UUID")

const (
	SizeAsBytes  = 16
	SizeAsString = 36
)

type UUID struct {
	Data []byte
}

func Parse(s string) (*UUID, error) {
	if len(s) != SizeAsString {
		return nil, ErrInvalidUUID
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return nil, ErrInvalidUUID
	}
	uuid := UUID{}
	// first three parts are little-endian
	offsets := []int{
		// first three parts are little-endian
		6, 4, 2, 0,
		11, 9,
		16, 14,
		// last two parts are big-endian
		19, 21,
		24, 26, 28, 30, 32, 34,
	}
	for _, off := range offsets {
		d, err := hex.DecodeString(s[off : off+2])
		if err != nil {
			return nil, err
		}
		uuid.Data = append(uuid.Data, d...)
	}
	return &uuid, nil
}

func FromBytes(data []byte) (*UUID, error) {
	var uuid UUID
	if len(data) != SizeAsBytes {
		return nil, ErrInvalidUUID
	}
	uuid.Data = append(uuid.Data, data...)
	return &uuid, nil
}

func (u UUID) String() string {
	var r string
	offsets := []int{
		3, 2, 1, 0,
		5, 4,
		7, 6,
		8, 9,
		10, 11, 12, 13, 14, 15,
	}
	for idx, off := range offsets {
		r += hex.EncodeToString([]byte{u.Data[off]})
		if idx == 3 || idx == 5 || idx == 7 || idx == 9 {
			r += "-"
		}
	}
	return r
}
