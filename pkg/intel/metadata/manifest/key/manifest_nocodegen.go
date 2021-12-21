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
	fmt.Printf("  --Key Manifest--\n")
	fmt.Printf("\t%v\n", m.StructInfo.PrettyString(1, true))
	fmt.Printf("\tKeyManifestSignatureOffset: %v\n", m.KeyManifestSignatureOffset)
	fmt.Printf("\tKMID: %v\n", m.KMID)
	fmt.Printf("\tPubKeyHashAlg: %v\n", m.PubKeyHashAlg)
	for _, i := range m.Hash {
		fmt.Printf("%v\n", i.PrettyString(2, true))
	}
	fmt.Printf("\n")
	if m.KeyAndSignature.Signature.DataTotalSize() < 1 {
		fmt.Printf("  --Key and Signature--\n")
		if m.KeyAndSignature.Key.DataTotalSize() > 0 {
			fmt.Printf("\t%v\n", m.KeyAndSignature.Key.PrettyString(2, true))
		}
		fmt.Printf("\n\n\tKey Manifest not signed!\n\n")
	} else {
		fmt.Printf("%v \n\n", m.KeyAndSignature.PrettyString(2, true))
	}
}
