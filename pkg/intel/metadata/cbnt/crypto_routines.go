// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"crypto"
	// Required for hash.Hash return in hashInfo struct
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
	"github.com/tjfoc/gmsm/sm3"
)

var hashInfo = []struct {
	alg         Algorithm
	hashFactory func() hash.Hash
}{
	{AlgSHA1, crypto.SHA1.New},
	{AlgSHA256, crypto.SHA256.New},
	{AlgSHA384, crypto.SHA384.New},
	{AlgSHA512, crypto.SHA512.New},
	{AlgSM3, sm3.New},
}

type Algorithm uint16

// IsNull returns true if a is AlgNull or zero (unset).
func (a Algorithm) IsNull() bool {
	return a == AlgNull || a == AlgUnknown
}

// Hash returns a crypto.Hash based on the given id.
// An error is returned if the given algorithm is not a hash algorithm or is not available.
func (a Algorithm) Hash() (hash.Hash, error) {
	for _, info := range hashInfo {
		if info.alg == a {
			if info.hashFactory == nil {
				return nil, fmt.Errorf("go hash algorithm #%snot available", info.alg.String())
			}
			return info.hashFactory(), nil
		}
	}
	return nil, fmt.Errorf("hash algorithm not supported: %s", a.String())
}

func (a Algorithm) String() string {
	var s strings.Builder
	var err error
	switch a {
	case AlgUnknown:
		_, err = s.WriteString("AlgUnknown")
	case AlgRSA:
		_, err = s.WriteString("RSA")
	case AlgSHA1:
		_, err = s.WriteString("SHA1")
	case AlgSHA256:
		_, err = s.WriteString("SHA256")
	case AlgSHA384:
		_, err = s.WriteString("SHA384")
	case AlgSHA512:
		_, err = s.WriteString("SHA512")
	case AlgSM3:
		_, err = s.WriteString("SM3")
	case AlgNull:
		_, err = s.WriteString("AlgNull")
	case AlgRSASSA:
		_, err = s.WriteString("RSASSA")
	case AlgRSAPSS:
		_, err = s.WriteString("RSAPSS")
	case AlgECDSA:
		_, err = s.WriteString("ECDSA")
	case AlgECC:
		_, err = s.WriteString("ECC")
	case AlgSM2:
		_, err = s.WriteString("SM2")
	default:
		return fmt.Sprintf("Alg?<%d>", int(a))
	}
	if err != nil {
		return fmt.Sprintf("Writing to string builder failed: %v", err)
	}
	return s.String()
}

func GetAlgFromString(name string) (Algorithm, error) {
	n := strings.ToUpper(name)
	switch n {
	case "ALGUNKNOWN":
		return AlgUnknown, nil
	case "RSA":
		return AlgRSA, nil
	case "SHA1":
		return AlgSHA1, nil
	case "SHA256":
		return AlgSHA256, nil
	case "SHA384":
		return AlgSHA384, nil
	case "SM3":
		return AlgSM3, nil
	case "ALGNULL":
		return AlgNull, nil
	case "RSASSA":
		return AlgRSASSA, nil
	case "RSAPSS":
		return AlgRSAPSS, nil
	case "ECDSA":
		return AlgECDSA, nil
	case "ECC":
		return AlgECC, nil
	case "SM2":
		return AlgSM2, nil
	default:
		return AlgNull, fmt.Errorf("algorithm name provided unknown")
	}
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (a Algorithm) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return a.String()
}

// TotalSize returns the total size measured through binary.Size.
func (a Algorithm) TotalSize() uint64 {
	return uint64(binary.Size(a))
}

// WriteTo writes the Algorithm into 'w' in binary format.
func (a Algorithm) WriteTo(w io.Writer) (int64, error) {
	return int64(a.TotalSize()), binary.Write(w, binary.LittleEndian, a)
}

// ReadFrom reads the Algorithm from 'r' in binary format.
func (a *Algorithm) ReadFrom(r io.Reader) (int64, error) {
	return int64(a.TotalSize()), binary.Read(r, binary.LittleEndian, a)
}
