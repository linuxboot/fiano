//go:generate manifestcodegen

package manifest

import (
	"crypto"
	"fmt"
	"hash"
	"strings"

	// Required for hash.Hash return in hashInfo struct
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/tjfoc/gmsm/sm3"
)

// MAX_DIGEST_BUFFER is the maximum size of []byte request or response fields.
// Typically used for chunking of big blobs of data (such as for hashing or
// encryption).
const maxDigestBuffer = 1024

// Algorithm represents a crypto algorithm value.
type Algorithm uint16

const (
	AlgUnknown Algorithm = 0x0000
	AlgRSA     Algorithm = 0x0001
	AlgSHA1    Algorithm = 0x0004
	AlgSHA256  Algorithm = 0x000B
	AlgSHA384  Algorithm = 0x000C
	AlgSHA512  Algorithm = 0x000D
	AlgNull    Algorithm = 0x0010
	AlgSM3_256 Algorithm = 0x0012
	AlgRSASSA  Algorithm = 0x0014
	AlgRSAPSS  Algorithm = 0x0016
	AlgECDSA   Algorithm = 0x0018
	AlgSM2     Algorithm = 0x001b
	AlgECC     Algorithm = 0x0023
)

var hashInfo = []struct {
	alg  Algorithm
	hash hash.Hash
}{
	{AlgSHA1, crypto.SHA1.New()},
	{AlgSHA256, crypto.SHA256.New()},
	{AlgSHA384, crypto.SHA384.New()},
	{AlgSHA512, crypto.SHA512.New()},
	{AlgSM3_256, sm3.New()},
}

// IsNull returns true if a is AlgNull or zero (unset).
func (a Algorithm) IsNull() bool {
	return a == AlgNull || a == AlgUnknown
}

// Hash returns a crypto.Hash based on the given id.
// An error is returned if the given algorithm is not a hash algorithm or is not available.
func (a Algorithm) Hash() (hash.Hash, error) {
	for _, info := range hashInfo {
		if info.alg == a {
			if info.hash == nil {
				return nil, fmt.Errorf("go hash algorithm #%snot available", info.alg.String())
			}
			return info.hash, nil
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
	case AlgSM3_256:
		_, err = s.WriteString("SM3_256")
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
