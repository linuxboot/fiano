// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tracedbinary

import (
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"runtime"
)

type ByteOrder = binary.ByteOrder

var (
	LittleEndian = binary.LittleEndian
)

func Read(r io.Reader, order ByteOrder, data interface{}) error {
	err := binary.Read(r, order, data)
	v := reflect.Indirect(reflect.ValueOf(data))
	switch {
	case v.Kind() != reflect.Slice || v.Len() < 16:
		fmt.Printf("%s: binary.Read(%T, %s, %T) -> %v; data == %v\n", caller(), r, order, data, err, v.Interface())
	case v.Kind() == reflect.Slice:
		fmt.Printf("%s: binary.Read(%T, %s, %T) -> %v; len(data) == %v\n", caller(), r, order, data, err, v.Len())
	default:
		fmt.Printf("%s: binary.Read(%T, %s, %T) -> %v\n", caller(), r, order, data, err)
	}
	return err
}

func Write(w io.Writer, order ByteOrder, data interface{}) error {
	err := binary.Write(w, order, data)
	fmt.Printf("%s: binary.Read(%T, %s, %T) -> %v\n", caller(), w, order, data, err)
	return err
}

func Size(v interface{}) int {
	r := binary.Size(v)
	fmt.Printf("%s: binary.Size(%T) -> %v\n", caller(), v, r)
	return r
}

func caller() string {
	_, file, line, _ := runtime.Caller(2)
	return fmt.Sprintf("%s:%d", filepath.Base(file), line)
}
