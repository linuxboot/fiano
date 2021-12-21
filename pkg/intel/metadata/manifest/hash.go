//go:generate manifestcodegen

package manifest

// HashStructure describes a digest.
type HashStructure struct {
	HashAlg    Algorithm `default:"0x10" json:"hsAlg"`
	HashBuffer []byte    `json:"hsBuffer"`
}

// HashList describes multiple digests
type HashList struct {
	Size uint16          `rehashValue:"TotalSize()" json:"hlSize"`
	List []HashStructure `json:"hlList"`
}
