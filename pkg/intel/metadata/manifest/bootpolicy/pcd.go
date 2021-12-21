//go:generate manifestcodegen

package bootpolicy

// PCD holds various Platform Config Data.
type PCD struct {
	StructInfo `id:"__PCDS__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
	Reserved0  [2]byte `json:"pcd_Reserved0,omitempty"`
	Data       []byte  `json:"pcd_Data"`
}
