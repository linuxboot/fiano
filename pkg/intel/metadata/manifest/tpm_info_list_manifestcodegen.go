package manifest

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/pretty"
)

var (
	// Just to avoid errors in "import" above in case if it wasn't used below
	_ = binary.LittleEndian
	_ = (fmt.Stringer)(nil)
	_ = (io.Reader)(nil)
	_ = pretty.Header
	_ = strings.Join
)

// NewTPMInfoList returns a new instance of TPMInfoList with
// all default values set.
func NewTPMInfoList() *TPMInfoList {
	s := &TPMInfoList{}
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *TPMInfoList) Validate() error {

	return nil
}

// ReadFrom reads the TPMInfoList from 'r' in format defined in the document #575623.
func (s *TPMInfoList) ReadFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// Capabilities (ManifestFieldType: endValue)
	{
		n, err := 4, binary.Read(r, binary.LittleEndian, &s.Capabilities)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Capabilities': %w", err)
		}
		totalN += int64(n)
	}

	// Algorithms (ManifestFieldType: list)
	{
		var count uint16
		err := binary.Read(r, binary.LittleEndian, &count)
		if err != nil {
			return totalN, fmt.Errorf("unable to read the count for field 'Algorithms': %w", err)
		}
		totalN += int64(binary.Size(count))
		s.Algorithms = make([]Algorithm, count)

		for idx := range s.Algorithms {
			err := binary.Read(r, binary.LittleEndian, &s.Algorithms[idx])
			if err != nil {
				return totalN, fmt.Errorf("unable to read field 'Algorithms[%d]': %w", idx, err)
			}
			totalN += int64(binary.Size(s.Algorithms[idx]))
		}
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *TPMInfoList) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *TPMInfoList) Rehash() {
}

// WriteTo writes the TPMInfoList into 'w' in format defined in
// the document #575623.
func (s *TPMInfoList) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// Capabilities (ManifestFieldType: endValue)
	{
		n, err := 4, binary.Write(w, binary.LittleEndian, &s.Capabilities)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Capabilities': %w", err)
		}
		totalN += int64(n)
	}

	// Algorithms (ManifestFieldType: list)
	{
		count := uint16(len(s.Algorithms))
		err := binary.Write(w, binary.LittleEndian, &count)
		if err != nil {
			return totalN, fmt.Errorf("unable to write the count for field 'Algorithms': %w", err)
		}
		totalN += int64(binary.Size(count))
		for idx := range s.Algorithms {
			n, err := binary.Size(s.Algorithms[idx]), binary.Write(w, binary.LittleEndian, s.Algorithms[idx])
			if err != nil {
				return totalN, fmt.Errorf("unable to write field 'Algorithms[%d]': %w", idx, err)
			}
			totalN += int64(n)
		}
	}

	return totalN, nil
}

// CapabilitiesSize returns the size in bytes of the value of field Capabilities
func (s *TPMInfoList) CapabilitiesTotalSize() uint64 {
	return 4
}

// AlgorithmsSize returns the size in bytes of the value of field Algorithms
func (s *TPMInfoList) AlgorithmsTotalSize() uint64 {
	var size uint64
	size += uint64(binary.Size(uint16(0)))
	for idx := range s.Algorithms {
		size += uint64(binary.Size(s.Algorithms[idx]))
	}
	return size
}

// CapabilitiesOffset returns the offset in bytes of field Capabilities
func (s *TPMInfoList) CapabilitiesOffset() uint64 {
	return 0
}

// AlgorithmsOffset returns the offset in bytes of field Algorithms
func (s *TPMInfoList) AlgorithmsOffset() uint64 {
	return s.CapabilitiesOffset() + s.CapabilitiesTotalSize()
}

// Size returns the total size of the TPMInfoList.
func (s *TPMInfoList) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	var size uint64
	size += s.CapabilitiesTotalSize()
	size += s.AlgorithmsTotalSize()
	return size
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *TPMInfoList) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "TPM Info List", s))
	}
	if s == nil {
		return strings.Join(lines, "\n")
	}
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "Capabilities", "", &s.Capabilities, opts...)...)
	// ManifestFieldType is list
	lines = append(lines, pretty.Header(depth+1, "Algorithms", nil))
	for _, alg := range s.Algorithms {
		lines = append(lines, pretty.SubValue(depth+2, "", "", alg, opts...)...)
	}
	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}
