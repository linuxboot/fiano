# Intel BG/CBnT Metadata

<!--toc:start-->
- [Intel BG/CBnT Metadata](#intel-bgcbnt-metadata)
  - [Structure](#structure)
  - [cbnt](#cbnt)
  - [bootpolicy](#bootpolicy)
  - [keymanifest](#keymanifest)
  - [Structure Modification/Extension](#structure-modificationextension)
    - [Types with Static Sizes](#types-with-static-sizes)
    - [Types with Dynamic Sizes](#types-with-dynamic-sizes)
    - [Field Type Quick Reference](#field-type-quick-reference)
    - [Adding a Structure](#adding-a-structure)
    - [Extending a Structure](#extending-a-structure)
<!--toc:end-->

This directory contains reusable definitions of common BG/CBnT structures and Boot Policy and Key Manifests for Intel platforms.

## Structure
```
├── cbnt                # Converged Boot Guard and TXT
│   ├── bootpolicy      # BG/CBnT Boot Policy Manifest
│   ├── keymanifest     # BG/CBnT Key Manifest
├── common              # Common elements
│   ├── examples
│   ├── manifestcodegen # Legacy code generator
│   ├── pretty          # Helper for printing the structures in human readable format
│   ├── tracedbinary
│   └── unittest        #
└── fit                 # Firmware Interface Table
```

## cbnt
The `cbnt` packages defines the structures that are used by both Boot Policy and Key Manifests. 
Most of the structures are shared between Boot Guard 1.0 and CBnT, with an exception for the following:

- Chipset AC Module Information
- TPM Info List
 
## bootpolicy
The `bootpolicy` package defines the Boot Policy Manifest and its child structures. In contrast with `cbnt`,
there are more differences between Boot Guard 1.0 and CBnT. Therefore, the Manifest constructor make the distinction
between the versions and returns the versioned implementation of the Manifest interface. Similar pattern is being used for
the structures that form the Manifest. 

The users of the `bootpolicy` packages should therefore make use of type assertions. These are safe in this context provided
that the constructor is feed with the supported version, and the error is handled correctly. An example usage:
```go
bpm, err := bootpolicy.NewManifest(cbnt.Version10)
if err != nil {
	return nil, err
}
bgbpm = bpm.(*bootpolicy.ManifestBG)
```

From that point on, the elements of the implementation may be accessed directly, for example:
```go
flags := bgbpm.SE[0].Flags
if !flags.AuthorityMeasure() {
	return false, fmt.Errorf("pcr-7 data should extended for OS security")
}
if !flags.TPMFailureLeavesHierarchiesEnabled() {
	return false, fmt.Errorf("tpm failure should lead to default measurements from PCR0 to PCR7")
}
```

## keymanifest
The `keymanifest` package defines the Key Manifest. It follows the same design as `bootpolicy`. An example usage:
```go
km, err := keymanifest.NewManifest(b.Version)
if err != nil {
	return nil, err
}
cbntkm = km.(*keymanifest.CBnTManifest)

hash := cbntkm.PubKeyHashAlg
		if hash == cbnt.AlgSHA1 || hash.IsNull() {
			return false, fmt.Errorf("KM signature uses insecure hash algorithm SHA1/Null")
		}
```

## Structure Modification/Extension
All the structures should implement the `Structure` interface (see [`cbnt/types.go`](cbnt/types.go)):
```go
Structure interface {
  io.ReaderFrom
	io.WriterTo
	TotalSize() uint64
	SizeOf(id int) (uint64, error)
	OffsetOf(id int) (uint64, error)
	Layout() []LayoutField
	Validate() error
	PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string
}
```

The most important method of the structure is the `Layout()` as it provides the `Common.ReadFrom()`, `Common.WriteTo()`, `Common.SizeOf()` and `Common.OffsetOf()` methods
with the information of the actual type the operation is supposed to be done. The common methods are accessed by letting all types to have `Common` struct
as a field.
> [!NOTE]
> `Common` struct should never be included in the `Layout()`! Otherwise, it will be treated as the actual part of the CBnT data structure.

### Types with Static Sizes
In most cases, that is, for the types that do not include fields that have their size determined at compile time, most of work is done in `Layout()`
method. Let's take `StructureInfoCBNT` as an example:
```go
func (s StructInfoCBNT) Layout() []LayoutField {
	return []LayoutField{
		{
			ID:    0,
			Name:  "ID",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.ID },
			Type:  ManifestFieldArrayStatic,
		},
		{
			ID:    1,
			Name:  "Version",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Version },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "Variable 0",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Variable0 },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    3,
			Name:  "Element Size",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.ElementSize },
			Type:  ManifestFieldEndValue,
		},
	}
}
```

All the values are known at compile time, and therefore the sizes defined in the specification can be filled in directly.

### Types with Dynamic Sizes
The types that have dynamic sizes are different beasts. They should still describe all fields through `Layout()`, but the `Size`
closure is computed from runtime values. The actual implementation is left for the person introducing a new type.

There are three "Types" of dynamic sized fields:
 - `ManifestFieldArrayDynamicWithSize` for byte arrays whose length is known from context (for example another field or algorithm-dependent size).
An example can be seen in `Key` type which is declared as:
```go
type Key struct {
	Common
	KeyAlg  Algorithm `json:"keyAlg"`
	Version uint8     `require:"0x10"  json:"keyVersion"`
	KeySize BitSize   `json:"keyBitsize"`
	Data    []byte    `countValue:"keyDataSize()" json:"keyData"`
}
```
The size of `Data` field is equal to the value of `KeySize` which is first determined once the structure is filled-in on a call to `Common.ReadFrom()`.
Therefore, the size closure in `Key`'s `Layout()` has to return the value of `KeySize`:
```go
{
	ID:    3,
	Name:  "Data",
	Size:  func() uint64 { return uint64(k.keyDataSize()) },
	Value: func() any { return &k.Data },
	Type:  ManifestFieldArrayDynamicWithSize,
},
```

- `ManifestFieldArrayDynamicWithPrefix` for byte arrays that carry their own size prefix on the wire. An example for such case is the `HashStructure` type declared as:
```go
type HashStructure struct {
	Common
	HashAlg    Algorithm `default:"0x10" json:"hsAlg"`
	HashBuffer []byte    `json:"hsBuffer"`
}
```

The size of `HashBuffer` is dynamic, but unlike `ManifestFieldArrayDynamicWithSize`, this encoding stores a `uint16`
length prefix before the actual bytes. Therefore, the `Size` closure includes both the prefix and the payload (which depends on the hash algorithm type):
```go
{
	ID:   1,
	Name: "Hash Buffer",
	Size: func() uint64 {
		h, err := s.HashAlg.Hash()
		if err != nil {
			return uint64(binary.Size(uint16(0)))
		}
		return uint64(binary.Size(uint16(0))) + uint64(h.Size())
	},
	Value: func() any { return &s.HashBuffer },
	Type:  ManifestFieldArrayDynamicWithPrefix,
},
```
Here, `binary.Size(uint16(0))` is the on-wire size prefix.

- `ManifestFieldList` for repeated items where count and element parsing/writing are custom; this requires `ReadList` and `WriteList` handlers. An example
for such case is the `HashList` type, declared as:
```go
type HashList struct {
	Common
	Size uint16          `rehashValue:"TotalSize()" json:"hlSize"`
	List []HashStructure `json:"hlList"`
}
```

Such types require addition fields to be returned in `Layout()`, and are an exception from the rule that all R/W logic is shared between the types. This is
motivated by the fact that `Common.ReadFrom()`/`Common.WriteTo()` cannot infer neither the type of the element on the list (well, it is possible with [reflection](https://go.dev/blog/laws-of-reflection),
though it would make common R/W methods look like dark magic), nor many elements should be processed and how each one should be
serialized. Therefore, `ReadList` and `WriteList` closures must be provided:
```go
{
	ReadList: func(r io.Reader) (int64, error) {
		var count uint16
		if err := binary.Read(r, endianess, &count); err != nil {
			return 0, fmt.Errorf("unable to read the count for field 'List': %w", err)
		}
		totalN := int64(binary.Size(count))
		s.List = make([]HashStructure, count)
		for idx := range s.List {
			n, err := s.List[idx].ReadFrom(r)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field 'List[%d]': %w", idx, err)
			}
			totalN += int64(n)
		}
		return totalN, nil
	},
	WriteList: func(w io.Writer) (int64, error) {
		count := uint16(len(s.List))
		if err := binary.Write(w, binary.LittleEndian, &count); err != nil {
			return 0, fmt.Errorf("unable to write the count for field 'List': %w", err)
		}
		totalN := int64(binary.Size(count))
		for idx := range s.List {
			n, err := s.List[idx].WriteTo(w)
			if err != nil {
				return totalN, fmt.Errorf("unable to write field 'List[%d]': %w", idx, err)
			}
			totalN += int64(n)
		}
		return totalN, nil
	},
},
```
Common R/W method will then call the closures and let them do type specific work.
Similarly as with other dynamic sizes, the closure has to provide the way of the runtime calculation that can be done
after the call to `Common.ReadFrom()`. An example `HashList`:

```go
{
	Size: func() uint64 {
		size := uint64(binary.Size(uint16(0)))
		for idx := range s.List {
			size += s.List[idx].Common.TotalSize(&s.List[idx])
		}
		return size
},
```

- `ManifestFieldSubStruct` for fields that represent another type that implement `Structure` interface. An example of such case is the `KeySignature` type declared as:
```go
type KeySignature struct {
	Common
	Version   uint8     `require:"0x10" json:"ksVersion,omitempty"`
	Key       Key       `json:"ksKey"`
	Signature Signature `json:"ksSignature"`
}
```

Effectively, in such case R/W and size/offsets of sub-types will be recursively determined using the common methods under the hood:
```go
	{
			ID:    1,
			Name:  "Key",
			Size:  func() uint64 { return s.Key.Common.TotalSize(&s.Key) },
			Value: func() any { return &s.Key },
			Type:  ManifestFieldSubStruct,
		},
		{
			ID:    2,
			Name:  "Signature",
			Size:  func() uint64 { return s.Signature.Common.TotalSize(&s.Signature) },
			Value: func() any { return &s.Signature },
			Type:  ManifestFieldSubStruct,
		},
```
As implementing entity of a type that contains fields with sub-types, there is no need to concern about **how** sub-type will perform R/W and size/offset determination, as
long it is known that its layout is correctly defined.

> [!NOTE]
> for all dynamic fields, keep `Size()` aligned with the exact binary representation consumed/written by that field type.

### Field Type Quick Reference
As described above, `Common.ReadFrom()` and `Common.WriteTo()` dispatch behavior by `LayoutField.Type`:

* `ManifestFieldEndValue`: plain fixed-size scalar value.
* `ManifestFieldArrayStatic`: fixed-size array.
* `ManifestFieldArrayDynamicWithSize`: dynamic byte array with externally defined size.
* `ManifestFieldArrayDynamicWithPrefix`: dynamic byte array with encoded size prefix.
* `ManifestFieldList`: custom list logic via `ReadList`/`WriteList`.
* `ManifestFieldSubStruct`: nested structure implementing `io.ReaderFrom`/`io.WriterTo`.

### Adding a Structure
This will be showcased on imaginary structure, let's call it `X`.

1. Declare the struct (in the example we will use all `ManifestFieldType` variants):
```go
// Represents X structure as defined in document #nnnnnn
type X struct {
	Common
	UUID        [16]byte        `json:"superUUIDforXstruct"`
	Version     uint8           `require:"0x32" json:"versionX"`
	Signature   Signature       `json:"signatureX"`
	HashList    []HashStructure `json:"hlList"`
	SizeOfData1 BitSize         `json:"szData1X"`
	Data1       []byte          `json:"data1X"`
	Data2       []byte          `json:"data2X"`
}
```

2. Define `Layout()` in strict on-wire order and map each field to a `ManifestFieldType`:
```go
func (s *X) Layout() []LayoutField {
	return []LayoutField{
		{
			ID:    0,
			Name:  "UUID",
			Size:  func() uint64 { return 16 },
			Value: func() any { return &s.UUID },
			Type:  ManifestFieldArrayStatic,
		},
		{
			ID:    1,
			Name:  "Version",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Version },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "Signature",
			Size:  func() uint64 { return s.Signature.Common.TotalSize(&s.Signature) },
			Value: func() any { return &s.Signature },
			Type:  ManifestFieldSubStruct,
		},
		{
			ID:   3,
			Name: fmt.Sprintf("Hash List: length %d", len(s.HashList)),
			Size: func() uint64 {
				size := uint64(binary.Size(uint16(0)))
				for idx := range s.HashList {
					size += s.HashList[idx].TotalSize()
				}
				return size
			},
			Value: func() any { return &s.HashList },
			Type:  ManifestFieldList,
			ReadList: func(r io.Reader) (int64, error) {
				var count uint16
				if err := binary.Read(r, endianess, &count); err != nil {
					return 0, fmt.Errorf("unable to read count for field 'HashList': %w", err)
				}
				totalN := int64(binary.Size(count))
				s.HashList = make([]HashStructure, count)
				for idx := range s.HashList {
					n, err := s.HashList[idx].ReadFrom(r)
					if err != nil {
						return totalN, fmt.Errorf("unable to read field 'HashList[%d]': %w", idx, err)
					}
					totalN += n
				}
				return totalN, nil
			},
			WriteList: func(w io.Writer) (int64, error) {
				count := uint16(len(s.HashList))
				if err := binary.Write(w, endianess, &count); err != nil {
					return 0, fmt.Errorf("unable to write count for field 'HashList': %w", err)
				}
				totalN := int64(binary.Size(count))
				for idx := range s.HashList {
					n, err := s.HashList[idx].WriteTo(w)
					if err != nil {
						return totalN, fmt.Errorf("unable to write field 'HashList[%d]': %w", idx, err)
					}
					totalN += n
				}
				return totalN, nil
			},
		},
		{
			ID:    4,
			Name:  "SizeOfData1",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.SizeOfData1 },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    5,
			Name:  "Data1",
			Size:  func() uint64 { return uint64(&s.SizeOfData1) },
			Value: func() any { return &s.Data1 },
			Type:  ManifestFieldArrayDynamicWithSize,
		},
		{
			ID:    6,
			Name:  "Data2",
			Size:  func() uint64 { return uint64(binary.Size(uint16(0)) + len(s.Data2)) },
			Value: func() any { return &s.Data2 },
			Type:  ManifestFieldArrayDynamicWithPrefix,
		},
	}
}
```

3. Keep common methods delegated to `Common`:
```go
func (s *X) ReadFrom(r io.Reader) (int64, error) { return s.Common.ReadFrom(r, s) }
func (s *X) WriteTo(w io.Writer) (int64, error) { return s.Common.WriteTo(w, s) }
func (s *X) TotalSize() uint64               { return s.Common.TotalSize(s) }
func (s *X) SizeOf(id int) (uint64, error)   { return s.Common.SizeOf(s, id) }
func (s *X) OffsetOf(id int) (uint64, error) { return s.Common.OffsetOf(s, id) }
func (s *X) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "X", opts...)
}
```

4. Implement `Validate()` and/or `Rehash()` if any values are derived from other fields, for example:
```go
func (s *X) Rehash() {
	s.SizeOfData1 = BitSize(len(s.Data1))
}

func (s *X) Validate() error {
	if int(s.SizeOfData1) != len(s.Data1) {
		return fmt.Errorf("field 'SizeOfData1' expects %d, but has %d", len(s.Data1), s.SizeOfData1)
	}
	return nil
}
```
If you need a completely new field behavior beyond existing `ManifestFieldType` values,
extend the `ManifestFieldType` constants and add corresponding handling in both
`Common.ReadFrom()` and `Common.WriteTo()`.

### Extending a Structure
Let's take `SECBnT` as an example here, and assume that the update specification adds a field that stores the size of `IBBSegments`. Then we need to adapt the following:
1. Type definition
```go
type SECBnT struct {
	cbnt.Common
	cbnt.StructInfoCBNT `id:"__IBBS__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
	Reserved0           [1]byte   `require:"0" json:"seReserved0,omitempty"`
	SetNumber           uint8     `require:"0" json:"seSetNumber,omitempty"`
	Reserved1           [1]byte   `require:"0" json:"seReserved1,omitempty"`
	PBETValue           PBETValue `json:"sePBETValue"`
	Flags               SEFlags   `json:"seFlags"`
	IBBMCHBAR uint64 `json:"seIBBMCHBAR"`
	VTdBAR uint64 `json:"seVTdBAR"`
	DMAProtBase0 uint32 `json:"seDMAProtBase0"`
	DMAProtLimit0 uint32 `json:"seDMAProtLimit0"`
	DMAProtBase1 uint64 `json:"seDMAProtBase1"`
	DMAProtLimit1 uint64 `json:"seDMAProtLimit1"`
	PostIBBHash cbnt.HashStructure `json:"sePostIBBHash"`
	IBBEntryPoint uint32 `json:"seIBBEntry"`
	DigestList cbnt.HashList `json:"seDigestList"`
	OBBHash cbnt.HashStructure `json:"seOBBHash"`
	Reserved2 [3]byte `require:"0" json:"seReserved2,omitempty"`
	// NEW: size of IBBSegments
	SizeOfIBBSeg [2]byte `json:"seSizeOfIBBSeg,omitemptu"`
	IBBSegments []IBBSegment `countType:"uint8" json:"seIBBSegments,omitempty"`
}
```

2. Layout descriptor
```go
func (s *SECBnT) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "Struct Info",
			Size:  func() uint64 { return s.StructInfoCBNT.TotalSize() },
			Value: func() any { return &s.StructInfoCBNT },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		...
		{
			ID:    16,
			Name:  "Reserved 2",
			Size:  func() uint64 { return 3 },
			Value: func() any { return &s.Reserved2 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		// New entry
		{
			ID:   17,
			Name: "Size of IBB Segments",
			Size: func() uint64 { return 2 },
			Value: func() any { return s.IBBSegments.TotalSize() }, // Yes, this example makes little sense, but it is more about the mechanics of the approach than logics of specification. 
			Type: cbnt.ManifestFieldArrayDynamicWithSize,
		}
		{
			ID:   18, // Incremented
			Name: fmt.Sprintf("IBBSegments: Array of \"IBB Segments Element\" of length %d", len(s.IBBSegments)),
			Size: func() uint64 {
		...
		}
}	
```

3. Any affected API calls

`SizeOf` and `OffsetOf` methods depend on the ID of a field. Thus, after modifying the layout descriptor, these have to be adjusted.


## Testing

There are two types of tests used for the metadata related packages:

- Unit Tests: for the structures in the `cbnt` packages.
- Integration Tests: for manifests. These are further described in a dedicated [README](/pkg/intel/metadata/common/integration/README.md).

To run all the tests:
```bash
go test ./cbnt
```
