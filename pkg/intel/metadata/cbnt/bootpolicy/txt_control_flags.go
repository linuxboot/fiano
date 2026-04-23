// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntbootpolicy

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

const (
	// <TO BE DOCUMENTED>
	CachingTypeWriteProtect = CachingType(iota)
	CachingTypeWriteBack
	CachingTypeReserved0
	CachingTypeReserved1
)

const (
	ExecutionProfileA = ExecutionProfile(iota)
	ExecutionProfileB
	ExecutionProfileC
)

const (
	MemoryScrubbingPolicyDefault = MemoryScrubbingPolicy(iota)
	MemoryScrubbingPolicyBIOS
	MemoryScrubbingPolicySACM
)

const (
	BackupActionPolicyDefault = BackupActionPolicy(iota)
	BackupActionPolicyForceMemoryPowerDown
	BackupActionPolicyForceBtGUnbreakableShutdown
)

const (
	ResetAUXControlResetAUXIndex = ResetAUXControl(iota)
	ResetAUXControlDeleteAUXIndex
)

type BackupActionPolicy uint8

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v BackupActionPolicy) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return v.String()
}

// TotalSize returns the total size measured through binary.Size.
func (v BackupActionPolicy) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the BackupActionPolicy into 'w' in binary format.
func (v BackupActionPolicy) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the BackupActionPolicy from 'r' in binary format.
func (v BackupActionPolicy) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v ExecutionProfile) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return v.String()
}

type ExecutionProfile uint8

// TotalSize returns the total size measured through binary.Size.
func (v ExecutionProfile) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the ExecutionProfile into 'w' in binary format.
func (v ExecutionProfile) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the ExecutionProfile from 'r' in binary format.
func (v ExecutionProfile) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

type MemoryScrubbingPolicy uint8

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v MemoryScrubbingPolicy) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return v.String()
}

// TotalSize returns the total size measured through binary.Size.
func (v MemoryScrubbingPolicy) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the MemoryScrubbingPolicy into 'w' in binary format.
func (v MemoryScrubbingPolicy) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the MemoryScrubbingPolicy from 'r' in binary format.
func (v MemoryScrubbingPolicy) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

type ResetAUXControl uint8

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v ResetAUXControl) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return v.String()
}

// TotalSize returns the total size measured through binary.Size.
func (v ResetAUXControl) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the ResetAUXControl into 'w' in binary format.
func (v ResetAUXControl) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the ResetAUXControl from 'r' in binary format.
func (v ResetAUXControl) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

type TXTControlFlags uint32

// PrettyString returns the bits of the flags in an easy-to-read format.
func (flags TXTControlFlags) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "TXT Control Flags", flags))
	}
	lines = append(lines, pretty.SubValue(depth+1, "Execution Profile", "", flags.ExecutionProfile(), opts...)...)
	lines = append(lines, pretty.SubValue(depth+1, "Memory Scrubbing Policy", "", flags.MemoryScrubbingPolicy(), opts...)...)
	lines = append(lines, pretty.SubValue(depth+1, "Backup Action Policy", "", flags.BackupActionPolicy(), opts...)...)
	if flags.IsSACMRequestedToExtendStaticPCRs() {
		lines = append(lines, pretty.SubValue(depth+1, "Is SACM Requested To Extend Static PC Rs", "Default setting. S-ACM is requested to extend static PCRs", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "Is SACM Requested To Extend Static PC Rs", "S-ACM is not requested to extend static PCRs", false, opts...)...)
	}
	lines = append(lines, pretty.SubValue(depth+1, "Reset AUX Control", "", flags.ResetAUXControl(), opts...)...)
	return strings.Join(lines, "\n")
}

// TotalSize returns the total size measured through binary.Size.
func (flags TXTControlFlags) TotalSize() uint64 {
	return uint64(binary.Size(flags))
}

// WriteTo writes the TXTControlFlags into 'w' in binary format.
func (flags TXTControlFlags) WriteTo(w io.Writer) (int64, error) {
	return int64(flags.TotalSize()), binary.Write(w, binary.LittleEndian, flags)
}

// ReadFrom reads the TXTControlFlags from 'r' in binary format.
func (flags TXTControlFlags) ReadFrom(r io.Reader) (int64, error) {
	return int64(flags.TotalSize()), binary.Read(r, binary.LittleEndian, flags)
}

func (flags TXTControlFlags) ExecutionProfile() ExecutionProfile {
	return ExecutionProfile(flags & 0x1f)
}

// String just implements fmt.Stringer.
func (v ExecutionProfile) String() string {
	switch v {
	case ExecutionProfileA:
		return `A (use default selection based on differentation between clients, UP, and MP servers)`
	case ExecutionProfileB:
		return `B (use "Server model": rely on BIOS to configure topoligy; do not use ACHECK)`
	case ExecutionProfileC:
		return `C (use "Client model": do not measure BIOS into D-PCRs; use ACHECK-based alias check)`
	}
	return fmt.Sprintf("unexpected_execution_profile_value_0x%02X", uint8(v))
}

func (flags TXTControlFlags) MemoryScrubbingPolicy() MemoryScrubbingPolicy {
	return MemoryScrubbingPolicy((flags >> 5) & 0x3)
}

// String implements fmt.Stringer.
func (v MemoryScrubbingPolicy) String() string {
	switch v {
	case MemoryScrubbingPolicyDefault:
		return "BIOS if verified or backup action othersize"
	case MemoryScrubbingPolicyBIOS:
		return "BIOS"
	case MemoryScrubbingPolicySACM:
		return "S-ACM"
	}
	return fmt.Sprintf("unexpected_value_0x%02X", uint8(v))
}

func (flags TXTControlFlags) BackupActionPolicy() BackupActionPolicy {
	return BackupActionPolicy((flags >> 7) & 0x3)
}

// String implements fmt.Stringer.
func (v BackupActionPolicy) String() string {
	switch v {
	case BackupActionPolicyDefault:
		return "memory power down if profile D or BtG unbreakable shutdown otherwise"
	case BackupActionPolicyForceMemoryPowerDown:
		return "memory power down"
	case BackupActionPolicyForceBtGUnbreakableShutdown:
		return "BtG unbreakable shutdown"
	}
	return fmt.Sprintf("unexpected_value_0x%02X", uint8(v))
}

// PrettyString-true:  Default setting. S-ACM is requested to extend static PCRs
// PrettyString-false: S-ACM is not requested to extend static PCRs
func (flags TXTControlFlags) IsSACMRequestedToExtendStaticPCRs() bool {
	return (flags>>9)&0x01 == 0
}

func (flags TXTControlFlags) ResetAUXControl() ResetAUXControl {
	return ResetAUXControl((flags >> 31) & 0x01)
}

// String implements fmt.Stringer.
func (v ResetAUXControl) String() string {
	switch v {
	case ResetAUXControlResetAUXIndex:
		return "AUX reset leaf will reset AUX index"
	case ResetAUXControlDeleteAUXIndex:
		return "AUX reset leaf will delete AUX index"
	}
	return fmt.Sprintf("unexpected_value_0x%02X", uint8(v))
}
