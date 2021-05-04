package fit

import (
	"bytes"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/key"
)

// ParseData creates EntryKeyManifestRecord from EntryKeyManifest
func (entry *EntryKeyManifestRecord) ParseData() (*key.Manifest, error) {
	var km key.Manifest
	_, err := km.ReadFrom(bytes.NewReader(entry.GetDataBytes()))
	if err != nil {
		return nil, fmt.Errorf("failed to parse KeyManifest, err: %v", err)
	}
	return &km, nil
}

// ParseKeyManifest returns a boot policy manifest if it was able to
// parse one.
func (table Table) ParseKeyManifest(firmware []byte) (*key.Manifest, error) {
	hdr := table.First(EntryTypeKeyManifestRecord)
	if hdr == nil {
		return nil, ErrNotFound{}
	}

	return hdr.GetEntry(firmware).(*EntryKeyManifestRecord).ParseData()
}
