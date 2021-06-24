//go:generate manifestcodegen

package bootpolicy

// PM is the platform manufacturer data element
type PM struct {
	StructInfo `id:"__PMDA__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
	Reserved0  [2]byte `require:"0" json:"pcReserved0,omitempty"`
	Data       []byte  `json:"pcData"`
}
