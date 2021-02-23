// +build !manifestcodegen
//
// To avoid errors "bpm.KeySignatureOffsetTotalSize undefined" and
// "bpm.BPMH.PrettyString undefined" we place these functions to a file
// with a build tag "!manifestcodegen"

package bootpolicy

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/pretty"
)

func (bpm *Manifest) rehashedBPMH() BPMH {
	bpmh := bpm.BPMH
	bpmh.KeySignatureOffset = uint16(bpm.PMSEOffset() + bpm.PMSE.KeySignatureOffset())
	return bpmh
}

// Print prints the Manifest
func (bpm Manifest) Print() {
	fmt.Printf("%v", bpm.BPMH.PrettyString(1, true))
	for _, item := range bpm.SE {
		fmt.Printf("%v", item.PrettyString(1, true))
	}
	if bpm.TXTE != nil {
		fmt.Printf("%v\n", bpm.TXTE.PrettyString(1, true))
	} else {
		fmt.Printf("  --TXTE--\n\t not set!(optional)\n")
	}

	if bpm.PCDE != nil {
		fmt.Printf("%v\n", bpm.PCDE.PrettyString(1, true))
	} else {
		fmt.Println("  --PCDE-- \n\tnot set!(optional)")
	}

	if bpm.PME != nil {
		fmt.Printf("%v\n", bpm.PME.PrettyString(1, true))
	} else {
		fmt.Println("  --PME--\n\tnot set!(optional)")
	}

	if bpm.PMSE.Signature.DataTotalSize() < 1 {
		fmt.Printf("%v\n", bpm.PMSE.PrettyString(1, true, pretty.OptionOmitKeySignature(true)))
		fmt.Printf("  --PMSE--\n\tBoot Policy Manifest not signed!\n\n")
	} else {
		fmt.Printf("%v\n", bpm.PMSE.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))
	}
}
