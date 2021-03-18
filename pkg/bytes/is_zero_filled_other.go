// +build !amd64

package bytes

// IsZeroFilled returns true if b consists of zeros only.
//go:nosplit
func IsZeroFilled(b []byte) bool {
	return isZeroFilledSimple(b)
}
