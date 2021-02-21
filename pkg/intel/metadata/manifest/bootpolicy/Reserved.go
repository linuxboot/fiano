//go:generate manifestcodegen

package bootpolicy

// Reserved is reducted
type Reserved struct {
	StructInfo   `id:"__PFRS__" version:"0x21" var0:"0" var1:"uint16(s.TotalSize())"`
	ReservedData [32]byte `json:"Reserved_Data"`
}
