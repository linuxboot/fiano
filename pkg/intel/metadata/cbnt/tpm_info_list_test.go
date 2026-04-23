// Copyright 2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestTPMInfoListNew(t *testing.T) {
	t.Parallel()

	tpm := NewTPMInfoList()
	if tpm == nil {
		t.Fatal("NewTPMInfoList() = nil, want non-nil")
	}
	if tpm.Capabilities != 0 {
		t.Errorf("NewTPMInfoList().Capabilities = %d, want %d", tpm.Capabilities, 0)
	}
	if len(tpm.Algorithms) != 0 {
		t.Errorf("len(NewTPMInfoList().Algorithms) = %d, want %d", len(tpm.Algorithms), 0)
	}
}

func TestTPMInfoListReadWriteRoundTrip(t *testing.T) {
	t.Parallel()

	want := &TPMInfoList{
		Capabilities: TPMCapabilities(0x3D),
		Algorithms:   []Algorithm{AlgSHA256, AlgSHA384, AlgSM3},
	}

	var buf bytes.Buffer
	n, err := want.WriteTo(&buf)
	if err != nil {
		t.Fatalf("TPMInfoList.WriteTo() error = %v, want nil", err)
	}
	if n != int64(want.TotalSize()) {
		t.Errorf("TPMInfoList.WriteTo() bytes = %d, want %d", n, want.TotalSize())
	}

	var got TPMInfoList
	n, err = got.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("TPMInfoList.ReadFrom() error = %v, want nil", err)
	}
	if n != int64(got.TotalSize()) {
		t.Errorf("TPMInfoList.ReadFrom() bytes = %d, want %d", n, got.TotalSize())
	}

	if got.Capabilities != want.Capabilities {
		t.Errorf("TPMInfoList round-trip Capabilities = 0x%x, want 0x%x", got.Capabilities, want.Capabilities)
	}
	if len(got.Algorithms) != len(want.Algorithms) {
		t.Fatalf("len(TPMInfoList round-trip Algorithms) = %d, want %d", len(got.Algorithms), len(want.Algorithms))
	}
	for idx := range want.Algorithms {
		if got.Algorithms[idx] != want.Algorithms[idx] {
			t.Errorf("TPMInfoList round-trip Algorithms[%d] = %v, want %v", idx, got.Algorithms[idx], want.Algorithms[idx])
		}
	}
}

func TestTPMInfoListMethods(t *testing.T) {
	t.Parallel()

	tpm := &TPMInfoList{Algorithms: []Algorithm{AlgSHA256}}

	size0, err := tpm.SizeOf(0)
	if err != nil {
		t.Fatalf("TPMInfoList.SizeOf(0) error = %v, want nil", err)
	}
	if size0 != 4 {
		t.Errorf("TPMInfoList.SizeOf(0) = %d, want %d", size0, 4)
	}

	offset1, err := tpm.OffsetOf(1)
	if err != nil {
		t.Fatalf("TPMInfoList.OffsetOf(1) error = %v, want nil", err)
	}
	if offset1 != 4 {
		t.Errorf("TPMInfoList.OffsetOf(1) = %d, want %d", offset1, 4)
	}

	if _, err := tpm.SizeOf(99); err == nil {
		t.Errorf("TPMInfoList.SizeOf(99) error = nil, want non-nil")
	}
	if _, err := tpm.OffsetOf(99); err == nil {
		t.Errorf("TPMInfoList.OffsetOf(99) error = nil, want non-nil")
	}

	var nilTPM *TPMInfoList
	if got := nilTPM.TotalSize(); got != 0 {
		t.Errorf("(*TPMInfoList)(nil).TotalSize() = %d, want %d", got, 0)
	}

	pretty := tpm.PrettyString(0, true)
	if !strings.Contains(pretty, "TPM Info List") {
		t.Errorf("TPMInfoList.PrettyString() = %q, want to contain %q", pretty, "TPM Info List")
	}
}

func TestTPMCapabilitiesAccessors(t *testing.T) {
	t.Parallel()

	cap := TPMCapabilities(0)
	cap |= TPMCapabilities(TPM2PCRExtendBothPolicies)
	cap |= TPMCapabilities(0x0D << 2)

	if got := cap.TPM2PCRExtendPolicySupport(); got != TPM2PCRExtendBothPolicies {
		t.Errorf("TPMCapabilities.TPM2PCRExtendPolicySupport() = %v, want %v", got, TPM2PCRExtendBothPolicies)
	}

	family := cap.TPMFamilySupport()
	if !family.IsDiscreteTPM12Supported() {
		t.Errorf("TPMFamilySupport.IsDiscreteTPM12Supported() = false, want true")
	}
	if !family.IsFirmwareTPM20Supported() {
		t.Errorf("TPMFamilySupport.IsFirmwareTPM20Supported() = false, want true")
	}
	if family.IsDiscreteTPM20Supported() {
		t.Errorf("TPMFamilySupport.IsDiscreteTPM20Supported() = true, want false")
	}
}

func TestTPMSimpleTypesReadWriteRoundTrip(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		write    func(*bytes.Buffer) (int64, error)
		read     func(*bytes.Buffer) (any, error)
		readFrom func(*bytes.Buffer) (int64, error)
		wantSize int64
		want     any
		wantErr  bool
		errSub   string
	}{
		"TPM2PCRExtendPolicySupport": {
			write: func(buf *bytes.Buffer) (int64, error) {
				v := TPM2PCRExtendPolicySupport(0x12)
				return v.WriteTo(buf)
			},
			read: func(buf *bytes.Buffer) (any, error) {
				var v TPM2PCRExtendPolicySupport
				if err := binary.Read(buf, binary.LittleEndian, &v); err != nil {
					return nil, err
				}
				return v, nil
			},
			readFrom: func(buf *bytes.Buffer) (int64, error) {
				var v TPM2PCRExtendPolicySupport
				return (&v).ReadFrom(buf)
			},
			wantSize: int64(TPM2PCRExtendPolicySupport(0).TotalSize()),
			want:     TPM2PCRExtendPolicySupport(0x12),
			wantErr:  true,
			errSub:   "invalid type",
		},
		"TPMCapabilities": {
			write: func(buf *bytes.Buffer) (int64, error) {
				v := TPMCapabilities(0x1234ABCD)
				return v.WriteTo(buf)
			},
			read: func(buf *bytes.Buffer) (any, error) {
				var v TPMCapabilities
				if err := binary.Read(buf, binary.LittleEndian, &v); err != nil {
					return nil, err
				}
				return v, nil
			},
			readFrom: func(buf *bytes.Buffer) (int64, error) {
				var v TPMCapabilities
				return (&v).ReadFrom(buf)
			},
			wantSize: int64(TPMCapabilities(0).TotalSize()),
			want:     TPMCapabilities(0x1234ABCD),
			wantErr:  true,
			errSub:   "invalid type",
		},
		"TPMFamilySupport": {
			write: func(buf *bytes.Buffer) (int64, error) {
				v := TPMFamilySupport(0x0D)
				return v.WriteTo(buf)
			},
			read: func(buf *bytes.Buffer) (any, error) {
				var v TPMFamilySupport
				if err := binary.Read(buf, binary.LittleEndian, &v); err != nil {
					return nil, err
				}
				return v, nil
			},
			readFrom: func(buf *bytes.Buffer) (int64, error) {
				var v TPMFamilySupport
				return (&v).ReadFrom(buf)
			},
			wantSize: int64(TPMFamilySupport(0).TotalSize()),
			want:     TPMFamilySupport(0x0D),
			wantErr:  true,
			errSub:   "invalid type",
		},
	}

	for name, tt := range tests {
		name := name
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var writeBuf bytes.Buffer
			n, err := tt.write(&writeBuf)
			if err != nil {
				t.Fatalf("%s.WriteTo() error = %v, want nil", name, err)
			}
			if n != tt.wantSize {
				t.Errorf("%s.WriteTo() bytes = %d, want %d", name, n, tt.wantSize)
			}

			decoded, err := tt.read(bytes.NewBuffer(writeBuf.Bytes()))
			if err != nil {
				t.Fatalf("binary.Read(%s) error = %v, want nil", name, err)
			}
			if decoded != tt.want {
				t.Errorf("%s round-trip decoded value = %v, want %v", name, decoded, tt.want)
			}

			n, err = tt.readFrom(bytes.NewBuffer(writeBuf.Bytes()))
			if tt.wantErr {
				if err == nil {
					t.Errorf("%s.ReadFrom() error = nil, want non-nil (current implementation uses value receiver)", name)
				} else if tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("%s.ReadFrom() error = %q, want substring %q", name, err.Error(), tt.errSub)
				}
			} else if err != nil {
				t.Errorf("%s.ReadFrom() error = %v, want nil", name, err)
			}
			if n != tt.wantSize {
				t.Errorf("%s.ReadFrom() bytes = %d, want %d", name, n, tt.wantSize)
			}
		})
	}
}
