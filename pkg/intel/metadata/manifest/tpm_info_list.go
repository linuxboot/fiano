//go:generate manifestcodegen
package manifest

type TPM2PCRExtendPolicySupport uint8

const (
	TPM2PCRExtendIllegal                  TPM2PCRExtendPolicySupport = 0
	TPM2PCRExtendMaximumAgilityPolicy     TPM2PCRExtendPolicySupport = 1
	TPM2PCRExtendMaximumPerformancePolicy TPM2PCRExtendPolicySupport = 2
	TPM2PCRExtendBothPolicies             TPM2PCRExtendPolicySupport = 3
)

type TPMFamilySupport uint8

func (familySupport TPMFamilySupport) IsDiscreteTPM12Supported() bool {
	return familySupport&1 != 0
}

func (familySupport TPMFamilySupport) IsDiscreteTPM20Supported() bool {
	return familySupport&2 != 0
}

func (familySupport TPMFamilySupport) IsFirmwareTPM20Supported() bool {
	return familySupport&(1<<3) != 0
}

type TPMCapabilities uint32

func (cap TPMCapabilities) TPM2PCRExtendPolicySupport() TPM2PCRExtendPolicySupport {
	return TPM2PCRExtendPolicySupport(cap & 3)
}

func (cap TPMCapabilities) TPMFamilySupport() TPMFamilySupport {
	return TPMFamilySupport((cap >> 2) & 15)
}

// TPMInfoList represents TPM capabilities supported by ACM
type TPMInfoList struct {
	Capabilities TPMCapabilities
	Algorithms   []Algorithm
}
