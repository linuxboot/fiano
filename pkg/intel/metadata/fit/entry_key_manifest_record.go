package fit

import (
	"bytes"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/key"
)

// Parse creates EntryKeyManifestRecord from EntryKeyManifest
func (entry *EntryKeyManifestRecord) ParseData() (*key.Manifest, error) {
	var km key.Manifest
	_, err := km.ReadFrom(bytes.NewReader(entry.GetDataBytes()))
	if err != nil {
		return nil, fmt.Errorf("failed to parse KeyManifest, err: %v", err)
	}
	return &km, nil
}
