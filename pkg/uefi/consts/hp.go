package consts

var (
	// HPSignedFileMagic is the magic used to detect if the firmware is actually
	// an HP signed container-file (so it's required to extract/find
	// the firmware image first).
	HPSignedFileMagic = []byte(`--=</Begin HP Signed File Fingerprint\>=--`)

	// HPImageMagic is the magic used to find the beginning of the real
	// firmware image inside of a HP signed container-file
	HPImageMagic = []byte(`HPIMAGE`)
)
