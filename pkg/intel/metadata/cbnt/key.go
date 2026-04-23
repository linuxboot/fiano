// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package cbnt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
	"github.com/tjfoc/gmsm/sm2"
)

type Key struct {
	Common
	KeyAlg  Algorithm `json:"keyAlg"`
	Version uint8     `require:"0x10"  json:"keyVersion"`
	KeySize BitSize   `json:"keyBitsize"`
	Data    []byte    `countValue:"keyDataSize()" json:"keyData"`
}

// keyDataSize returns the expected length of Data for specified
// KeyAlg and KeySize.
func (k Key) keyDataSize() int64 {
	switch k.KeyAlg {
	case AlgRSA:
		return int64(k.KeySize.InBytes()) + 4
	case AlgECC, AlgSM2:
		return int64(k.KeySize.InBytes()) * 2
	}
	return -1
}

// PubKey parses Data into crypto.PublicKey.
func (k Key) PubKey() (crypto.PublicKey, error) {
	expectedSize := int(k.keyDataSize())
	if expectedSize < 0 {
		return nil, fmt.Errorf("unexpected algorithm: %s", k.KeyAlg)
	}
	if len(k.Data) != expectedSize {
		return nil, fmt.Errorf("unexpected size: expected:%d, received %d", expectedSize, len(k.Data))
	}

	switch k.KeyAlg {
	case AlgRSA:
		result := &rsa.PublicKey{
			N: new(big.Int).SetBytes(reverseBytes(k.Data[4:])),
			E: int(endianess.Uint32(k.Data)),
		}
		return result, nil
	case AlgECC:
		keySize := k.KeySize.InBytes()
		x := new(big.Int).SetBytes(reverseBytes(k.Data[:keySize]))
		y := new(big.Int).SetBytes(reverseBytes(k.Data[keySize:]))
		return ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	case AlgSM2:
		keySize := k.KeySize.InBytes()
		x := new(big.Int).SetBytes(reverseBytes(k.Data[:keySize]))
		y := new(big.Int).SetBytes(reverseBytes(k.Data[keySize:]))
		return sm2.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	}

	return nil, fmt.Errorf("unexpected TPM algorithm: %s", k.KeyAlg)
}

func reverseBytes(b []byte) []byte {
	r := make([]byte, len(b))
	for idx := range b {
		r[idx] = b[len(b)-idx-1]
	}
	return r
}

// SetPubKey sets Data the value corresponding to passed `key`.
func (k *Key) SetPubKey(key crypto.PublicKey) error {
	k.Version = 0x10

	switch key := key.(type) {
	case *rsa.PublicKey:
		k.KeyAlg = AlgRSA
		n := key.N.Bytes()
		k.KeySize.SetInBytes(uint16(len(n)))
		k.Data = make([]byte, 4+len(n))
		endianess.PutUint32(k.Data, uint32(key.E))
		copy(k.Data[4:], reverseBytes(n))
		return nil

	case *ecdsa.PublicKey:
		var x, y *big.Int
		k.KeyAlg = AlgECC
		x, y = key.X, key.Y
		if x == nil || y == nil {
			return fmt.Errorf("the pubkey '%#+v' is invalid: x == nil || y == nil", key)
		}
		k.KeySize.SetInBits(256)
		xB, yB := x.Bytes(), y.Bytes()
		if len(xB) != int(k.KeySize.InBytes()) || len(yB) != int(k.KeySize.InBytes()) {
			return fmt.Errorf("the pubkey '%#+v' is invalid: len(x)<%d> != %d || len(y)<%d> == %d",
				key, len(xB), int(k.KeySize.InBytes()), len(yB), int(k.KeySize.InBytes()))
		}
		k.Data = make([]byte, 2*k.KeySize.InBytes())
		copy(k.Data[:], reverseBytes(xB))
		copy(k.Data[len(xB):], reverseBytes(yB))
		return nil

	case *sm2.PublicKey:
		var x, y *big.Int
		k.KeyAlg = AlgSM2
		x, y = key.X, key.Y
		if x == nil || y == nil {
			return fmt.Errorf("the pubkey '%#+v' is invalid: x == nil || y == nil", key)
		}
		k.KeySize.SetInBits(256)
		xB, yB := x.Bytes(), y.Bytes()
		if len(xB) != int(k.KeySize.InBytes()) || len(yB) != int(k.KeySize.InBytes()) {
			return fmt.Errorf("the pubkey '%#+v' is invalid: len(x)<%d> != %d || len(y)<%d> == %d",
				key, len(xB), int(k.KeySize.InBytes()), len(yB), int(k.KeySize.InBytes()))
		}
		k.Data = make([]byte, 2*k.KeySize.InBytes())
		copy(k.Data[:], reverseBytes(xB))
		copy(k.Data[len(xB):], reverseBytes(yB))
		return nil
	}

	return fmt.Errorf("unexpected key type: %T", key)
}

// PrintBPMPubKey prints the BPM public signing key hash to fuse into the Intel ME
func (k *Key) PrintBPMPubKey(bpmAlg Algorithm) error {
	buf := new(bytes.Buffer)
	if len(k.Data) > 1 {
		hash, err := bpmAlg.Hash()
		if err != nil {
			return err
		}
		switch k.KeyAlg {
		case AlgRSA:
			if err := binary.Write(buf, binary.LittleEndian, k.Data[4:]); err != nil {
				return err
			}
			if _, err := hash.Write(buf.Bytes()); err != nil {
				return fmt.Errorf("unable to hash: %w", err)
			}
			fmt.Printf("   Boot Policy Manifest Pubkey Hash: 0x%x\n", hash.Sum(nil))
		case AlgSM2, AlgECC:
			if err := binary.Write(buf, binary.LittleEndian, k.Data); err != nil {
				return err
			}
			if _, err := hash.Write(buf.Bytes()); err != nil {
				return fmt.Errorf("unable to hash: %w", err)
			}
			fmt.Printf("   Boot Policy Manifest Pubkey Hash: 0x%x\n", hash.Sum(nil))
		default:
			fmt.Printf("   Boot Policy Manifest Pubkey Hash: Unknown Algorithm\n")
		}
	} else {
		fmt.Printf("   Boot Policy Pubkey Hash: No km public key set in KM\n")
	}

	return nil
}

// PrintKMPubKey prints the KM public signing key hash to fuse into the Intel ME
func (k *Key) PrintKMPubKey(kmAlg Algorithm) error {
	buf := new(bytes.Buffer)
	if len(k.Data) > 1 {
		if k.KeyAlg == AlgRSA {
			if err := binary.Write(buf, binary.LittleEndian, k.Data[4:]); err != nil {
				return err
			}
			if err := binary.Write(buf, binary.LittleEndian, k.Data[:4]); err != nil {
				return err
			}
			if kmAlg != AlgSHA256 && kmAlg != AlgSHA384 {
				return fmt.Errorf("KM public key hash algorithm must be SHA256 or SHA384")
			}
			hash, err := kmAlg.Hash()
			if err != nil {
				return err
			}
			if _, err := hash.Write(buf.Bytes()); err != nil {
				return fmt.Errorf("unable to hash: %w", err)
			}
			fmt.Printf("   Key Manifest Pubkey Hash: 0x%x\n", hash.Sum(nil))
			// On SKL and KBL the exponent is not included in the KM hash
			buf.Truncate(len(k.Data[4:]))
			hash.Reset()
			if _, err := hash.Write(buf.Bytes()); err != nil {
				return fmt.Errorf("unable to hash: %w", err)
			}
			fmt.Printf("   Key Manifest Pubkey Hash (Skylake and Kabylake only): 0x%x\n", hash.Sum(nil))
		} else {
			fmt.Printf("   Key Manifest Pubkey Hash: Unsupported Algorithm\n")
		}
	} else {
		fmt.Printf("   Key Manifest Pubkey Hash: No km public key set in KM\n")
	}

	return nil
}

// NewKey returns a new instance of Key with
// all default values set.
func NewKey() *Key {
	s := &Key{}
	// Set through tag "required":
	s.Version = 0x10
	return s
}

func (k *Key) Layout() []LayoutField {
	return []LayoutField{
		{
			ID:    0,
			Name:  "Key Alg",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &k.KeyAlg },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    1,
			Name:  "Version",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &k.Version },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "Key Size",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &k.KeySize },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    3,
			Name:  "Data",
			Size:  func() uint64 { return uint64(k.keyDataSize()) },
			Value: func() any { return &k.Data },
			Type:  ManifestFieldArrayDynamicWithSize,
		},
	}
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (k *Key) Validate() error {
	// See tag "require"
	if k.Version != 0x10 {
		return fmt.Errorf("field 'Version' expects value '0x10', but has %v", k.Version)
	}

	return nil
}

// ReadFrom reads the Key from 'r' in format defined in the document #575623.
func (k *Key) ReadFrom(r io.Reader) (int64, error) {
	totalN, err := k.Common.ReadFrom(r, k)
	if err != nil {
		return 0, err
	}

	return totalN, nil
}

// WriteTo writes the Key into 'w' in format defined in
// the document #575623.
func (k *Key) WriteTo(w io.Writer) (int64, error) {
	return k.Common.WriteTo(w, k)
}

func (k *Key) SizeOf(id int) (uint64, error) {
	ret, err := k.Common.SizeOf(k, id)
	if err != nil {
		// normally it would be 0, but ret is already 0 if we land here
		return ret, fmt.Errorf("Key: %v", err)
	}

	return ret, nil
}

func (k *Key) OffsetOf(id int) (uint64, error) {
	ret, err := k.Common.OffsetOf(k, id)
	if err != nil {
		return ret, fmt.Errorf("Key: %v", err)
	}

	return ret, nil
}

// Size returns the total size of the Key.
func (k *Key) TotalSize() uint64 {
	if k == nil {
		return 0
	}

	return k.Common.TotalSize(k)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (k *Key) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return Common{}.PrettyString(depth, withHeader, k, "Key", opts...)
}

type BitSize uint16

// InBits returns the size in bits.
func (ks BitSize) InBits() uint16 {
	return uint16(ks)
}

// InBytes returns the size in bytes.
func (ks BitSize) InBytes() uint16 {
	return uint16(ks >> 3)
}

// SetInBits sets the size in bits.
func (ks *BitSize) SetInBits(amountOfBits uint16) {
	*ks = BitSize(amountOfBits)
}

// SetInBytes sets the size in bytes.
func (ks *BitSize) SetInBytes(amountOfBytes uint16) {
	*ks = BitSize(amountOfBytes << 3)
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (ks BitSize) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "Bit Size", ks))
	}
	lines = append(lines, pretty.SubValue(depth+1, "In Bits", "", ks.InBits(), opts...)...)
	lines = append(lines, pretty.SubValue(depth+1, "In Bytes", "", ks.InBytes(), opts...)...)
	return strings.Join(lines, "\n")
}

// TotalSize returns the total size measured through binary.Size.
func (ks BitSize) TotalSize() uint64 {
	return uint64(binary.Size(ks))
}

// WriteTo writes the BitSize into 'w' in binary format.
func (ks BitSize) WriteTo(w io.Writer) (int64, error) {
	return int64(ks.TotalSize()), binary.Write(w, binary.LittleEndian, ks)
}

// ReadFrom reads the BitSize from 'r' in binary format.
func (ks BitSize) ReadFrom(r io.Reader) (int64, error) {
	return int64(ks.TotalSize()), binary.Read(r, binary.LittleEndian, ks)
}
