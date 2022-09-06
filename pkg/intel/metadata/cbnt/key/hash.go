// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package key

import (
	"fmt"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
)

// Hash is "KM hash Structure" defined in document #575623.
type Hash struct {
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
