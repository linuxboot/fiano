# Integration Tests

Since the majority of types share the same methods, most tests can be generalized.

For each manifest there are sample binaries corresponding to different versions:
 - `cbnt/bootpolicy/testdata/bpm10.bin` - BPM complying with Boot Guard 1.0
 - `cbnt/bootpolicy/testdata/bpm20.bin` - BPM complying with CBnT 2.0
 - `cbnt/bootpolicy/testdata/bpm21.bin` - BPM complying with CBnT 2.1
 - `cbnt/keymanifest/testdata/km_bg.bin` - KM complying with Boot Guard 1.0
 - `cbnt/keymanifest/testdata/km_cbnt.bin` - KM complying with CBnT 2.x

The integration test entrypoint is `ManifestReadWrite()` from `common/integration/read_write.go`.
It reads the provided binary into a Manifest implementation and then validates the full read/write contract:

- reads exactly the manifest bytes and ignores trailing data
- verifies `SizeOf()` and `OffsetOf()` for all top-level fields
- verifies `GetStructInfo()` and `SetStructInfo()` accessors
- validates manifest invariants via `Validate()`
- verifies `TotalSize()` matches bytes consumed by `ReadFrom()`
- checks `Print()` output against signed/unsigned expected patterns
- serializes with `WriteTo()` and verifies a byte-for-byte round trip against the original input from `ReadFrom()`
- recursively verifies size/offset behavior for nested structures and structure lists

The helper also checks that `PrettyString()` output is stable before and after serialization (note: it the coverage is low here given that the output is hard to generalize).

## Adding integration tests for a new manifest version

1. Add the sample binary to the package `testdata/` directory.
2. Instantiate the manifest with the right version in `manifest_test.go`.
3. Call `integration.ManifestReadWrite(t, m, "testdata/<file>.bin")`.

Example:

```go
func TestReadWriteCBNT2x(t *testing.T) {
	m, err := NewManifest(cbnt.Version2x)
	if err != nil {
		t.Fatalf("%v", err)
	}
	integration.ManifestReadWrite(t, m, "testdata/bpm2x.bin")
}
```
