// Copyright 2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"log"
	"os"
)

// Logger describes a logger to be used in fiano.
type Logger interface {
	// Warnf logs an warning message.
	Warnf(format string, args ...interface{})

	// Errorf logs an error message.
	Errorf(format string, args ...interface{})

	// Fatalf logs a fatal message and immediately exits the application
	// with os.Exit.
	Fatalf(format string, args ...interface{})
}

// DefaultLogger is the logger used by default everywhere within fiano.
var DefaultLogger Logger

func init() {
	DefaultLogger = logWrapper{Logger: log.New(os.Stderr, "", log.LstdFlags)}
}

type logWrapper struct {
	Logger *log.Logger
}

// Warnf implements Logger.
func (logger logWrapper) Warnf(format string, args ...interface{}) {
	logger.Logger.Printf("[fiano][WARN] "+format, args...)
}

// Errorf implements Logger.
func (logger logWrapper) Errorf(format string, args ...interface{}) {
	logger.Logger.Printf("[fiano][ERROR] "+format, args...)
}

// Fatalf implements Logger.
func (logger logWrapper) Fatalf(format string, args ...interface{}) {
	logger.Logger.Fatalf("[fiano][FATAL] "+format, args...)
}

// Warnf logs an warning message.
func Warnf(format string, args ...interface{}) {
	DefaultLogger.Warnf(format, args...)
}

// Errorf logs an error message.
func Errorf(format string, args ...interface{}) {
	DefaultLogger.Errorf(format, args...)
}

// Fatalf logs a fatal message and immediately exits the application
// with os.Exit (which is expected to be called by the DefaultLogger.Fatalf).
func Fatalf(format string, args ...interface{}) {
	DefaultLogger.Fatalf(format, args...)
}
