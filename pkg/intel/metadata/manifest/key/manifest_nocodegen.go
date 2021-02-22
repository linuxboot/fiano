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
	fmt.Printf("%v\n", m.PrettyString(1, true))
}
