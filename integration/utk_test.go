package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Returns all the ROM names (files which end in .rom) inside the roms folder.
func romList(t *testing.T) []string {
	roms, err := filepath.Glob("roms/*.rom")
	if err != nil {
		t.Fatalf("could not glob roms/*.rom, %v", err)
	}
	if len(roms) == 0 {
		t.Fatal("no ROMs found with roms/*.rom")
	}
	return roms
}

// Builds UTK into temporary directory.
func buildUTK(t *testing.T) (tmpDir string, utk string) {
	// Create temporary directory for test files.
	var err error
	tmpDir, err = ioutil.TempDir("", "utk-test")
	if err != nil {
		t.Fatalf("could not create temp dir: %v", err)
	}

	// Build UTK in the tmpDir.
	cmd := exec.Command("go", "build", "github.com/linuxboot/fiano/utk")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("could not build UTK: %v", err)
	}
	utk = filepath.Join(tmpDir, "utk")

	return
}

// TestParse tests the parse subcommand of UTK. The amount of testing is
// negligible. This simply tests that valid ROMs produce valid JSON. Warnings
// are printed but ignored.
func TestParse(t *testing.T) {
	// Build UTK.
	tmpDir, utk := buildUTK(t)
	defer os.RemoveAll(tmpDir)

	for _, tt := range romList(t) {
		t.Run(tt, func(t *testing.T) {
			// Run `utk parse --warn tt.rom`.
			cmd := exec.Command(utk, "parse", "--warn", tt)
			cmd.Stderr = os.Stderr
			out, err := cmd.Output()

			// Warnings are acceptable as long as valid JSON is outputted.
			if err != nil {
				t.Log("non-zero exit status returned")
			}

			var dec interface{}
			err = json.Unmarshal(out, &dec)
			if err != nil {
				t.Errorf("invalid json: %q", string(out))
			}
		})
	}
}

// TestExtractAssembleExtract tests the extract and assemble subcommand of UTK.
// The subcommands are run in this order:
//
// 1. utk extract tt.rom dir1
// 2. utk assemble dir1 tmp.rom
// 3. utk extract tmp.rom dir2
//
// The test passes iff the contents or dir1 and dir2 recursively equal. This
// roundabout method is used because UTK can re-assemble a ROM image which is
// logically equal to the original, but not bitwise equal (due to a different
// compression algorithm being used). To compare the ROMs logically, step 3 is
// required to decompresses it.
func TestExtractAssembleExtract(t *testing.T) {
	// Build UTK.
	tmpDir, utk := buildUTK(t)
	defer os.RemoveAll(tmpDir)

	for _, tt := range romList(t) {
		t.Run(tt, func(t *testing.T) {
			// Test paths
			var (
				dir1   = filepath.Join(tmpDir, "dir1")
				tmpRom = filepath.Join(tmpDir, "tmp.rom")
				dir2   = filepath.Join(tmpDir, "dir2")
			)

			// Warnings are acceptable.
			cmd := exec.Command(utk, "extract", "--warn", tt, dir1)
			cmd.Stderr = os.Stderr
			cmd.Run()
			cmd = exec.Command(utk, "assemble", dir1, tmpRom)
			cmd.Stderr = os.Stderr
			cmd.Run()
			cmd = exec.Command(utk, "extract", "--warn", tmpRom, dir2)
			cmd.Stderr = os.Stderr
			cmd.Run()

			// Output directories must not be empty.
			for _, d := range []string{dir1, dir2} {
				files, err := ioutil.ReadDir(d)
				if err != nil {
					t.Fatalf("cannot read directory %q: %v", d, err)
				}
				if len(files) == 0 {
					t.Errorf("no files in directory %q", d)
				}
			}

			// TODO: make summary.json paths relative so this hack can be removed.
			exec.Command("sed", "-i", "s/dir2/dir1/", filepath.Join(dir2, "summary.json")).Run()

			// Recursively test for equality.
			cmd = exec.Command("diff", "-r", dir1, dir2)
			cmd.Stderr = os.Stderr
			cmd.Stdout = os.Stdout
			if err := cmd.Run(); err != nil {
				t.Error("directories did not recursively compare equal")
			}
		})
	}
}
