// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntkey

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// Hash is "KM hash Structure" defined in document #575623.
type Hash struct {
	cbnt.Common
	// Usage is the digest usage bitmask.
	//
	// More than one bit can be set to indicate shared digest usage.
	// Usage of bit 0 is normative; other usages are informative.
	Usage Usage `json:"hashUsage"`

	// Digest is the actual digest.
	Digest cbnt.HashStructure `json:"hashStruct"`
}

// Usage is the digest usage bitmask.
//
// More than one bit can be set to indicate shared digest usage.
// Usage of bit 0 is normative; other usages are informative.
type Usage uint64

const (
	// UsageBPMSigningPKD is the bit meaning the digest could be used as
	// Boot Policy Manifest signing pubkey digest.
	UsageBPMSigningPKD = Usage(1 << iota)

	// UsageFITPatchManifestSigningPKD is the bit meaning the digest could be used as
	// FIT Patch Manifest signing pubkey digest.
	UsageFITPatchManifestSigningPKD

	// UsageACMManifestSigningPKD is the bit meaning the digest could be used as
	// ACM Manifest signing pubkey digest.
	UsageACMManifestSigningPKD

	// UsageSDEVSigningPKD is the bit meaning the digest could be used as
	// SDEV signing pubkey digest.
	UsageSDEVSigningPKD

	// UsageReserved is a reserved bit
	UsageReserved
)

// String implements fmt.Stringer.
func (u Usage) String() string {
	var result []string
	for i := uint(0); i < 64; i++ {
		f := Usage(1 << i)
		if !u.IsSet(f) {
			continue
		}
		var descr string
		switch f {
		case UsageBPMSigningPKD:
			descr = "BPM_signing_pubkey_digest"
		case UsageFITPatchManifestSigningPKD:
			descr = "FIT_patch_manifest_signing_pubkey_digest"
		case UsageACMManifestSigningPKD:
			descr = "ACM_manifest_signing_pubkey_digest"
		case UsageSDEVSigningPKD:
			descr = "SDEV_signing_pubkey_digest"
		case UsageReserved:
			descr = "Reserved"
		default:
			descr = fmt.Sprintf("unexpected_bit_%d", i)
		}
		result = append(result, descr)
	}

	return strings.Join(result, ",")
}

// IsSet returns true if bits `f` are set in bitmask `u`.
func (u Usage) IsSet(f Usage) bool {
	return u&f != 0
}

// Set sets/unsets the bits of `f` in bitmask `u`.
//
// To set the bits `v` should be true, to unset -- false.
func (u *Usage) Set(f Usage, v bool) {
	if v {
		*u |= f
	} else {
		*u &= ^f
	}
}

// NewHash returns a new instance of Hash with
// all default values set.
func NewHash() *Hash {
	s := &Hash{}
	// Recursively initializing a child structure:
	// s.Digest = *cbnt.NewHashStructure()
	// s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *Hash) Validate() error {
	// Recursively validating a child structure:
	// if err := s.Digest.Validate(); err != nil {
	// 	return fmt.Errorf("error on field 'Digest': %w", err)
	// }

	return nil
}

// ReadFrom reads the Hash from 'r' in format defined in the document #575623.
func (s *Hash) ReadFrom(r io.Reader) (int64, error) {
	totalN, err := s.Common.ReadFrom(r, s)
	if err != nil {
		return 0, err
	}

	return totalN, nil
}

// WriteTo writes the Hash into 'w' in format defined in
// the document #575623.
func (s *Hash) WriteTo(w io.Writer) (int64, error) {
	return s.Common.WriteTo(w, s)
}

func (s *Hash) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "Usage",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.Usage },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    1,
			Name:  "Digest",
			Size:  func() uint64 { return s.Digest.Common.TotalSize(&s.Digest) },
			Value: func() any { return &s.Digest },
			Type:  cbnt.ManifestFieldSubStruct,
		},
	}
}

func (s *Hash) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		// normally it would be 0, but ret is already 0 if we land here
		return ret, fmt.Errorf("Hash: %v", err)
	}

	return ret, nil
}

func (s *Hash) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Hash: %v", err)
	}

	return ret, nil
}

// Size returns the total size of the Hash.
func (s *Hash) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *Hash) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "Hash", opts...)
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (u Usage) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return u.String()
}

// TotalSize returns the total size measured through binary.Size.
func (u Usage) TotalSize() uint64 {
	return uint64(binary.Size(u))
}

// WriteTo writes the Usage into 'w' in binary format.
func (u Usage) WriteTo(w io.Writer) (int64, error) {
	return int64(u.TotalSize()), binary.Write(w, binary.LittleEndian, u)
}

// ReadFrom reads the Usage from 'r' in binary format.
func (u Usage) ReadFrom(r io.Reader) (int64, error) {
	return int64(u.TotalSize()), binary.Read(r, binary.LittleEndian, u)
}
