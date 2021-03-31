package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"reflect"
	"strings"
	"text/template"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/manifestcodegen/pkg/analyze"
	"github.com/fatih/camelcase"
)

type methodsData struct {
	analyze.File
	EnableTracing bool
}

// generateMethodsFile generates a file using the template above.
//
// The file name is constructed from the original file name, but with
// adding suffix '_manifestcodegen' before the file extension.
func generateMethodsFile(file analyze.File, isCheck, enableTracing bool) error {
	funcsMap := map[string]interface{}{
		"add": func(a, b int) int { return a + b },
		"ternary": func(cond bool, a, b interface{}) interface{} {
			if cond {
				return a
			}
			return b
		},
		"isNil": func(v interface{}) bool {
			return reflect.ValueOf(v).IsNil()
		},
		"camelcaseToSentence": func(in string) string {
			return strings.Join(camelcase.Split(in), " ")
		},
	}

	if len(file.Structs) == 0 && len(file.BasicNamedTypes) == 0 {
		return nil
	}

	templateMethods, err := template.New("methods").Funcs(funcsMap).Parse(templateMethods)
	if err != nil {
		return fmt.Errorf("unable to parse the template: %w", err)
	}
	if ext := path.Ext(file.Path); ext != ".go" {
		return fmt.Errorf("invalid extension: '%s'", ext)
	}
	generatedFile := fmt.Sprintf("%s_manifestcodegen.go",
		file.Path[:len(file.Path)-3],
	)

	var outFile string
	if isCheck {
		outFile = generatedFile + "-check.go"
	} else {
		outFile = generatedFile
	}

	f, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("unable to open file '%s' for writing: %w", outFile, err)
	}
	defer func() {
		if isCheck {
			err := os.Remove(outFile)
			if err != nil {
				log.Printf("unable to remove file '%s': %v\n", outFile, err)
			}
		}
		err := f.Close()
		if err != nil {
			log.Printf("unable to close file '%s': %v\n", outFile, err)
		}
	}()

	err = templateMethods.Execute(f, methodsData{
		File:          file,
		EnableTracing: enableTracing,
	})
	if err != nil {
		return fmt.Errorf("unable to write: %w", err)
	}
	err = exec.Command("go", "fmt", outFile).Run()
	if err != nil {
		return fmt.Errorf("unable to format file '%s': %w", outFile, err)
	}

	if isCheck {
		b0, err := ioutil.ReadFile(outFile)
		if err != nil {
			return fmt.Errorf("unable to read a temp file '%s'", outFile)
		}
		b1, err := ioutil.ReadFile(generatedFile + "~")
		if err != nil {
			return fmt.Errorf("unable to read file '%s'", generatedFile)
		}
		if bytes.Compare(b0, b1) != 0 {
			return fmt.Errorf("file '%s' is not up-to-date; please run command: "+
				"go run github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/manifestcodegen/cmd/manifestcodegen %s",
				generatedFile, file.Package.Path())
		}
	}
	return nil
}
