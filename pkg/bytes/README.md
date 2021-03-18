```
goos: linux
goarch: amd64
BenchmarkIsZeroFilled/size_0/default-8 	1000000000	         3.03 ns/op	       0 B/op	       0 allocs/op
BenchmarkIsZeroFilled/size_0/simple-8  	1000000000	         2.93 ns/op	       0 B/op	       0 allocs/op
BenchmarkIsZeroFilled/size_1/default-8 	1000000000	         4.74 ns/op	       0 B/op	       0 allocs/op
BenchmarkIsZeroFilled/size_1/simple-8  	1000000000	         3.31 ns/op	       0 B/op	       0 allocs/op
BenchmarkIsZeroFilled/size_256/default-8         	212255557	        28.4 ns/op	       0 B/op	       0 allocs/op
BenchmarkIsZeroFilled/size_256/simple-8          	71001369	        86.8 ns/op	       0 B/op	       0 allocs/op
BenchmarkIsZeroFilled/size_65536/default-8       	 1466428	      3961 ns/op	       0 B/op	       0 allocs/op
BenchmarkIsZeroFilled/size_65536/simple-8        	  308932	     19780 ns/op	       0 B/op	       0 allocs/op
BenchmarkIsZeroFilled/size_1048576/default-8     	  106068	     65791 ns/op	       0 B/op	       0 allocs/op
BenchmarkIsZeroFilled/size_1048576/simple-8      	   17924	    335547 ns/op	       0 B/op	       0 allocs/op
PASS
ok  	_/home/xaionaro/go/src/github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/pkg/bytes	63.711s
```