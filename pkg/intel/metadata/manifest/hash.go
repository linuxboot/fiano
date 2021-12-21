//go:generate manifestcodegen

package manifest

import "github.com/google/go-tpm/tpm2"

// HashStructure describes a digest.
type HashStructure struct {
	HashAlg    tpm2.Algorithm `default:"0x10" json:"hs_Alg"`
	HashBuffer []byte         `json:"hs_Buffer"`
}

// HashList describes multiple digests
type HashList struct {
	Size uint16 `rehashValue:"TotalSize()"`
	List []HashStructure
}
