package bytes

//go:nosplit
func isZeroFilledSimple(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
