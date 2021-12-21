package manifest

// SVN represents Security Version Number.
type SVN uint8

// SVN returns the Security Version Number of an SVN field
func (svn SVN) SVN() uint8 {
	return uint8(svn) & 0x0f
}
