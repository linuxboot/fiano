// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/manifestcodegen/pkg/analyze"
)

func deleteBackupFiles(dirPath string) error {
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("unable to open '%s' as dir: %w", dirPath, err)
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), "_manifestcodegen.go~") {
			continue
		}

		path := filepath.Join(dirPath, file.Name())
		err := os.Remove(path)
		if err != nil {
			return fmt.Errorf("unable to delete file '%s': %w", path, err)
		}
	}

	return nil
}

func backupGeneratedFiles(dirPath string, isReverse bool) error {
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("unable to open '%s' as dir: %w", dirPath, err)
	}

	suffix := "_manifestcodegen.go"
	if isReverse {
		suffix += "~"
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), suffix) {
			continue
		}

		var err error
		path := filepath.Join(dirPath, file.Name())
		if isReverse {
			err = os.Rename(path, path[:len(path)-1])
		} else {
			err = os.Rename(path, path+"~")
		}
		if err != nil {
			return fmt.Errorf("unable to delete file '%s': %w", path, err)
		}
	}

	return nil
}

func processPath(path string, isCheck, enableTracing bool) error {
	if stat, err := os.Stat(path); err == nil && stat.IsDir() {
		err := backupGeneratedFiles(path, false)
		if err != nil {
			return fmt.Errorf("unable to rename old generated files: %w", err)
		}
	}

	var goPaths []string
	if gopathEnv := os.Getenv("GOPATH"); gopathEnv != "" {
		goPaths = filepath.SplitList(gopathEnv)
	} else {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("unable to determine the homedir: %w", err)
		}

		goPaths = append(goPaths, filepath.Join(homeDir, "go"))
	}

	dirInfo, err := analyze.Scan(path, goPaths)
	if err != nil {
		return fmt.Errorf("unable to analyze path '%s': %w", path, err)
	}

	for _, fileInfo := range dirInfo.Files {
		err := generateMethodsFile(*fileInfo, isCheck, enableTracing)
		if err != nil {
			_ = backupGeneratedFiles(path, true)
			return err
		}
	}

	if isCheck {
		err := backupGeneratedFiles(path, true)
		if err != nil {
			return fmt.Errorf("unable to rename back old generated files: %w", err)
		}
	} else {
		err := deleteBackupFiles(path)
		if err != nil {
			return fmt.Errorf("unable to rename back old generated files: %w", err)
		}
	}

	return nil
}

func processPaths(paths []string, checkFlag, traceFlag bool) int {
	errorCount := 0
	for _, path := range paths {
		err := processPath(path, checkFlag, traceFlag)
		if err != nil {
			log.Printf("an error: %v", err)
			errorCount++
		}
	}

	return errorCount
}

func main() {
	checkFlag := flag.Bool("check", false, "generate with tracing code")
	traceFlag := flag.Bool("trace", false, "generate with tracing code")
	flag.Parse()

	var paths []string

	switch {
	case flag.NArg() > 0:
		paths = append(paths, flag.Args()...)
	case os.Getenv("GOFILE") != "":
		paths = append(paths, os.Getenv("GOFILE"))
	default:
		paths = append(paths, ".")
	}

	errorCount := processPaths(paths, *checkFlag, *traceFlag)
	if errorCount != 0 {
		os.Exit(1)
	}
}
