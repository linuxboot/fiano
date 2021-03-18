package fit

import (
	"bytes"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/bootpolicy"
)

// Parse creates EntryKeyManifestRecord from EntryKeyManifest
func (entry *EntryBootPolicyManifestRecord) ParseData() (*bootpolicy.Manifest, error) {
	var bpManifest bootpolicy.Manifest
	_, err := bpManifest.ReadFrom(bytes.NewReader(entry.GetDataBytes()))
	if err != nil {
		return nil, fmt.Errorf("failed to parse KeyManifest, err: %v", err)
	}
	return &bpManifest, nil
}
