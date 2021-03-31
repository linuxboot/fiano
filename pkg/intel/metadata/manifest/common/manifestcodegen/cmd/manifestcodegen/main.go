package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/manifestcodegen/pkg/analyze"
)

func assertNoError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func deleteBackupFiles(dirPath string) error {
	files, err := ioutil.ReadDir(dirPath)
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
	files, err := ioutil.ReadDir(dirPath)
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

func replaceInFiles(dirPath, oldValue, newValue string) {
	// ugly terrible hack to workaround versioning support
	// TODO: fix the importer to recognize `/v2/` as version, not as path
	files, err := ioutil.ReadDir(dirPath)
	assertNoError(err)

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".go") {
			continue
		}
		filePath := filepath.Join(dirPath, file.Name())
		contents, err := ioutil.ReadFile(filePath)
		assertNoError(err)
		contents = bytes.Replace(contents, []byte(oldValue), []byte(newValue), -1)
		err = ioutil.WriteFile(filePath, contents, 0640)
		assertNoError(err)
	}
}

func processPath(path string, isCheck, enableTracing bool) error {
	if stat, err := os.Stat(path); err == nil && stat.IsDir() {
		err := backupGeneratedFiles(path, false)
		if err != nil {
			return fmt.Errorf("unable to rename old generated files: %w", err)
		}
	}

	// ugly terrible hack to workaround versioning support
	// TODO: fix the importer to recognize `/v2/` as version, not as path
	os.Setenv("GO111MODULE", "off")

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
	for _, path := range paths {
		// ugly terrible hack to workaround versioning support
		// TODO: fix the importer to recognize `/v2/` as version, not as path
		replaceInFiles(path, "converged-security-suite/v2/pkg", "converged-security-suite/pkg")
	}
	defer func() {
		for _, path := range paths {
			replaceInFiles(path, "converged-security-suite/pkg", "converged-security-suite/v2/pkg")
		}
	}()

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
