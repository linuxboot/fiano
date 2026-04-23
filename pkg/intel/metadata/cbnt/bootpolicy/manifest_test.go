// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntbootpolicy

import (
	"testing"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/integration"
)

func TestReadWriteBG(t *testing.T) {
	m, err := NewManifest(cbnt.Version10)
	if err != nil {
		t.Fatalf("%v", err)
	}
	integration.ManifestReadWrite(t, m, "testdata/bpm10.bin")
}

func TestReadWriteCBNT(t *testing.T) {
	m, err := NewManifest(cbnt.Version20)
	if err != nil {
		t.Fatalf("%v", err)
	}
	integration.ManifestReadWrite(t, m, "testdata/bpm20.bin")
}

func TestReadWriteCBNT21(t *testing.T) {
	m, err := NewManifest(cbnt.Version21)
	if err != nil {
		t.Fatalf("%v", err)
	}
	integration.ManifestReadWrite(t, m, "testdata/bpm21.bin")
}
