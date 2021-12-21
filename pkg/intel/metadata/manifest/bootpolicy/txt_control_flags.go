//go:generate manifestcodegen

package bootpolicy

import (
	"fmt"
)

type TXTControlFlags uint32

func (flags TXTControlFlags) ExecutionProfile() ExecutionProfile {
	return ExecutionProfile(flags & 0x1f)
}

type ExecutionProfile uint8

const (
	ExecutionProfileA = ExecutionProfile(iota)
	ExecutionProfileB
	ExecutionProfileC
)

// String just implements fmt.Stringer.
func (p ExecutionProfile) String() string {
	switch p {
	case ExecutionProfileA:
		return `A (use default selection based on differentation between clients, UP, and MP servers)`
	case ExecutionProfileB:
		return `B (use "Server model": rely on BIOS to configure topoligy; do not use ACHECK)`
	case ExecutionProfileC:
		return `C (use "Client model": do not measure BIOS into D-PCRs; use ACHECK-based alias check)`
	}
	return fmt.Sprintf("unexpected_execution_profile_value_0x%02X", uint8(p))
}

func (flags TXTControlFlags) MemoryScrubbingPolicy() MemoryScrubbingPolicy {
	return MemoryScrubbingPolicy((flags >> 5) & 0x3)
}

type MemoryScrubbingPolicy uint8

const (
	MemoryScrubbingPolicyDefault = MemoryScrubbingPolicy(iota)
	MemoryScrubbingPolicyBIOS
	MemoryScrubbingPolicySACM
)

// String implements fmt.Stringer.
func (policy MemoryScrubbingPolicy) String() string {
	switch policy {
	case MemoryScrubbingPolicyDefault:
		return "BIOS if verified or backup action othersize"
	case MemoryScrubbingPolicyBIOS:
		return "BIOS"
	case MemoryScrubbingPolicySACM:
		return "S-ACM"
	}
	return fmt.Sprintf("unexpected_value_0x%02X", uint8(policy))
}

func (flags TXTControlFlags) BackupActionPolicy() BackupActionPolicy {
	return BackupActionPolicy((flags >> 7) & 0x3)
}

type BackupActionPolicy uint8

const (
	BackupActionPolicyDefault = BackupActionPolicy(iota)
	BackupActionPolicyForceMemoryPowerDown
	BackupActionPolicyForceBtGUnbreakableShutdown
)

// String implements fmt.Stringer.
func (policy BackupActionPolicy) String() string {
	switch policy {
	case BackupActionPolicyDefault:
		return "memory power down if profile D or BtG unbreakable shutdown otherwise"
	case BackupActionPolicyForceMemoryPowerDown:
		return "memory power down"
	case BackupActionPolicyForceBtGUnbreakableShutdown:
		return "BtG unbreakable shutdown"
	}
	return fmt.Sprintf("unexpected_value_0x%02X", uint8(policy))
}

// PrettyString-true:  Default setting. S-ACM is requested to extend static PCRs
// PrettyString-false: S-ACM is not requested to extend static PCRs
func (flags TXTControlFlags) IsSACMRequestedToExtendStaticPCRs() bool {
	return (flags>>9)&0x01 == 0
}

func (flags TXTControlFlags) ResetAUXControl() ResetAUXControl {
	return ResetAUXControl((flags >> 31) & 0x01)
}

type ResetAUXControl uint8

const (
	ResetAUXControlResetAUXIndex = ResetAUXControl(iota)
	ResetAUXControlDeleteAUXIndex
)

// String implements fmt.Stringer.
func (c ResetAUXControl) String() string {
	switch c {
	case ResetAUXControlResetAUXIndex:
		return "AUX reset leaf will reset AUX index"
	case ResetAUXControlDeleteAUXIndex:
		return "AUX reset leaf will delete AUX index"
	}
	return fmt.Sprintf("unexpected_value_0x%02X", uint8(c))
}
