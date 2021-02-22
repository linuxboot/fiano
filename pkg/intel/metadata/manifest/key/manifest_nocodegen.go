// +build !manifestcodegen
//
// To avoid error "m.StructInfo.PrettyString undefined" we place this
// function to a file with a build tag "!manifestcodegen"

package key

import (
	"fmt"
)

// Print prints the Key Manifest.
func (m *Manifest) Print() {
	if m.KeyAndSignature.Signature.DataTotalSize() < 1 {
		fmt.Printf("%v\n", m.PrettyString(1, true, false))
		fmt.Printf("  --KeyAndSignature--\n\tKey Manifest not signed!\n\n")
	} else {
		fmt.Printf("%v\n", m.PrettyString(1, true, true))
	}
}
