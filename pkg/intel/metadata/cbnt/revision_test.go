// Copyright 2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestBootGuardVersionString(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in   BootGuardVersion
		want string
	}{
		"version_1_0": {in: Version10, want: "1.0"},
		"version_2_0": {in: Version20, want: "2.0"},
		"version_2_1": {in: Version21, want: "2.1"},
		"unknown":     {in: BootGuardVersion(0xFF), want: "unknown"},
	}

	for name, tt := range tests {
		name := name
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := tt.in.String(); got != tt.want {
				t.Errorf("BootGuardVersion(%d).String() = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDetectBGV(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version byte
		want    BootGuardVersion
		wantErr bool
		errSub  string
	}{
		{name: "0x10_to_v1_0", version: 0x10, want: Version10},
		{name: "0x20_to_v2_0", version: 0x20, want: Version20},
		{name: "0x21_to_v2_0", version: 0x21, want: Version20},
		{name: "0x22_to_v2_1", version: 0x22, want: Version21},
		{name: "0x23_to_v2_1", version: 0x23, want: Version21},
		{name: "0x24_to_v2_1", version: 0x24, want: Version21},
		{name: "0x25_to_v2_1", version: 0x25, want: Version21},
		{name: "unknown", version: 0x99, wantErr: true, errSub: "couldn't detect version"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := bytes.NewReader(rawStructInfoVersion(tt.version))
			got, err := DetectBGV(r)
			if tt.wantErr {
				if err == nil {
					t.Errorf("DetectBGV(version 0x%x) error = nil, want non-nil", tt.version)
				} else if tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("DetectBGV(version 0x%x) error = %q, want substring %q", tt.version, err.Error(), tt.errSub)
				}
			} else if err != nil {
				t.Fatalf("DetectBGV(version 0x%x) error = %v, want nil", tt.version, err)
			} else if got != tt.want {
				t.Errorf("DetectBGV(version 0x%x) = %v, want %v", tt.version, got, tt.want)
			}

			if pos, err := r.Seek(0, io.SeekCurrent); err != nil {
				t.Fatalf("reader.Seek(current) error = %v, want nil", err)
			} else if pos != 0 {
				t.Errorf("reader position after DetectBGV() = %d, want %d", pos, 0)
			}
		})
	}
}

func TestDetectBGVErrorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		r      io.ReadSeeker
		errSub string
	}{
		{name: "read_error", r: bytes.NewReader(nil), errSub: "unable to read field 'ID'"},
		{name: "seek_error", r: seekFailReadSeeker{r: bytes.NewReader(rawStructInfoVersion(0x20))}, errSub: "seek failed"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := DetectBGV(tt.r)
			if err == nil {
				t.Fatalf("DetectBGV(%s) error = nil, want non-nil", tt.name)
			}
			if !strings.Contains(err.Error(), tt.errSub) {
				t.Errorf("DetectBGV(%s) error = %q, want substring %q", tt.name, err.Error(), tt.errSub)
			}
		})
	}
}

func rawStructInfoVersion(version byte) []byte {
	b := make([]byte, 12)
	b[8] = version
	return b
}

type seekFailReadSeeker struct {
	r io.Reader
}

func (s seekFailReadSeeker) Read(p []byte) (int, error) {
	return s.r.Read(p)
}

func (s seekFailReadSeeker) Seek(offset int64, whence int) (int64, error) {
	return 0, errors.New("seek failed")
}
