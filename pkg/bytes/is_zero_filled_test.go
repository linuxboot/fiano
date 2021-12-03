// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bytes

import (
	"fmt"
	"testing"
)

func BenchmarkIsZeroFilled(b *testing.B) {
	for _, size := range []uint64{0, 1, 256, 65536, 1 << 20} {
		d := make([]byte, size)
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			b.Run("default", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					IsZeroFilled(d)
				}
			})
			b.Run("simple", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					isZeroFilledSimple(d)
				}
			})
		})
	}
}
