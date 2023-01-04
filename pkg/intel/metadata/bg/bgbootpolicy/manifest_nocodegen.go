// Copyright 2017-2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !manifestcodegen
// +build !manifestcodegen

//
// To avoid errors "bpm.KeySignatureOffsetTotalSize undefined" and
// "bpm.BPMH.PrettyString undefined" we place these functions to a file
// with a build tag "!manifestcodegen"

package bgbootpolicy

import (
	"fmt"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

func (bpm *Manifest) rehashedBPMH() BPMH {
	return bpm.BPMH
}

// Print prints the Manifest
func (bpm Manifest) Print() {
	fmt.Printf("%v", bpm.BPMH.PrettyString(1, true))
	for _, item := range bpm.SE {
		fmt.Printf("%v", item.PrettyString(1, true))
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
