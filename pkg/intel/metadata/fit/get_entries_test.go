package fit

import (
	"bytes"
	"compress/bzip2"
	"encoding/base64"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	fitHeadersSampleBZ2, _ = base64.StdEncoding.DecodeString(
		"QlpoOTFBWSZTWeqFfFEBARl/z/6cAAhAEAJAISIUAMAAYADAABBMUgACAI4AAAiwANiQkhUepkNBk0A0Gj0nqGMmmQMmhkGRpgRgVJRHqBPUGmBPQQB6mu/KQvlYVFwVWSqIERBhUJJEkSR53rKJMcLkAQB4VEmzyuIBAGNSSaLY2elZ4gEAapJc7BvQ6GAOz3zzwaWQh1wYvXevCRHSI64eYVYAyTeHJJpz9TxxkkkkkgAA+ewChlSjX5WsDQH+LuSKcKEh1Qr4og==")
)

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}

func TestGetEntries(t *testing.T) {
	firmwareBytes, err := ioutil.ReadAll(bzip2.NewReader(bytes.NewReader(fitHeadersSampleBZ2)))
	panicIfError(err)

	entries, err := GetEntries(firmwareBytes)
	assert.NoError(t, err)

	assert.Equal(t, 27, len(entries))
}

// BenchmarkGetEntries-8             520621              2357 ns/op            2944 B/op         59 allocs/op
func BenchmarkGetEntries(b *testing.B) {
	firmwareBytes, err := ioutil.ReadAll(bzip2.NewReader(bytes.NewReader(fitHeadersSampleBZ2)))
	panicIfError(err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetEntries(firmwareBytes)
	}
}
