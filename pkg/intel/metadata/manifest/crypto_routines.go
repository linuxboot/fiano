package manifest

import (
	"crypto"
	"fmt"
	"strings"
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
	hash crypto.Hash
}{
	{AlgSHA1, crypto.SHA1},
	{AlgSHA256, crypto.SHA256},
	{AlgSHA384, crypto.SHA384},
	{AlgSHA512, crypto.SHA512},
}

// HashToAlgorithm looks up the manifest algorithm corresponding to the provided crypto.Hash
func HashToAlgorithm(hash crypto.Hash) (Algorithm, error) {
	for _, info := range hashInfo {
		if info.hash == hash {
			return info.alg, nil
		}
	}
	return AlgUnknown, fmt.Errorf("go hash algorithm #%d has no manifest algorithm", hash)
}

// IsNull returns true if a is AlgNull or zero (unset).
func (a Algorithm) IsNull() bool {
	return a == AlgNull || a == AlgUnknown
}

// Hash returns a crypto.Hash based on the given id.
// An error is returned if the given algorithm is not a hash algorithm or is not available.
func (a Algorithm) Hash() (crypto.Hash, error) {
	for _, info := range hashInfo {
		if info.alg == a {
			if !info.hash.Available() {
				return crypto.Hash(0), fmt.Errorf("go hash algorithm #%d not available", info.hash)
			}
			return info.hash, nil
		}
	}
	return crypto.Hash(0), fmt.Errorf("hash algorithm not supported: 0x%x", a)
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
