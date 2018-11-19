// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// futk is a forth-inspired infterface to utk.
// It is in a state of flux just now.
// Typical usage, and note that our first command is in argv, and they could all (or none) be in argv:
// rminnich@uroot:~/go/src/github.com/linuxboot/fiano/cmds/futk$ ./futk 7106V100.ROM fv # fv reads in a firmware volume
//    2018/11/21 09:14:29 Found 413 things
//    413
//    OK Tcp|Pxe|Udp ix r r tag
//    [6D6963AB-906D-4A65-A7CA-BD40E5D6AF2B:EFI_FV_FILETYPE_DRIVER:Udp4Dxe D912C7BC-F098-4367-92BA-E911083C7B0E:EFI_FV_FILETYPE_DRIVER:Udp6Dxe B95E9FDA-26DE-48D2-8807-1F9107AC5E3A:EFI_FV_FILETYPE_DRIVER:UefiPxeBcDxe 1A7E4468-2F55-4A56-903C-01265EB7622B:EFI_FV_FILETYPE_DRIVER:TcpDxe]
//    OK Tcp|Pxe|Udp ix status
//    1A7E4468-2F55-4A56-903C-01265EB7622B:EFI_FV_FILETYPE_DRIVER:TcpDxe: tags map[r:r]
//    6D6963AB-906D-4A65-A7CA-BD40E5D6AF2B:EFI_FV_FILETYPE_DRIVER:Udp4Dxe: tags map[r:r]
//    D912C7BC-F098-4367-92BA-E911083C7B0E:EFI_FV_FILETYPE_DRIVER:Udp6Dxe: tags map[r:r]
//    B95E9FDA-26DE-48D2-8807-1F9107AC5E3A:EFI_FV_FILETYPE_DRIVER:UefiPxeBcDxe: tags map[r:r]
//
//    OK bzImage.uroot splat
//    [7C04A583-9E3E-4F1C-AD65-E05268D0B4D1:EFI_FV_FILETYPE_APPLICATION:FullShell]
//    OK go
//    [/tmp/futkblacklist753009682 /tmp/futkrom522877513]
//    OK
// The r tags means those DXEs are removed before writing.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/linuxboot/fiano/pkg/uefi"
	"github.com/linuxboot/fiano/pkg/visitors"
	"github.com/u-root/u-root/pkg/forth"
)

const (
	keep    = "k"
	remove  = "r"
	removed = "R"
)

// Track information about files we found.
// We record the res used to find it and
// the states we assigned to it.
type (
	info struct {
		GUID  string
		name  string
		ftype uefi.FVFileType
		tags  map[string]string
	}
	cmd struct {
		c string
		h string
		f forth.Op
	}
)

var (
	fv uefi.Firmware
	// Track the files we have marked as keep, remove, or unknown.
	files   = map[uefi.Firmware]*info{}
	notouch = map[uefi.FVFileType]bool{
		uefi.FVFileTypeRaw:                true,
		uefi.FVFileTypeFreeForm:           true,
		uefi.FVFileTypeSECCore:            true,
		uefi.FVFileTypePEICore:            true,
		uefi.FVFileTypeDXECore:            true,
		uefi.FVFileTypePEIM:               true,
		uefi.FVFileTypeDriver:             false,
		uefi.FVFileTypeCombinedPEIMDriver: true,
		uefi.FVFileTypeApplication:        false,
		uefi.FVFileTypeSMM:                true,
		uefi.FVFileTypeVolumeImage:        true,
		uefi.FVFileTypeCombinedSMMDXE:     true,
		uefi.FVFileTypeSMMCore:            true,
		uefi.FVFileTypeSMMStandalone:      true,
		uefi.FVFileTypeSMMCoreStandalone:  true,
		uefi.FVFileTypeOEMMin:             true,
		uefi.FVFileTypeOEMMax:             true,
		uefi.FVFileTypeDebugMin:           true,
		uefi.FVFileTypeDebugMax:           true,
		uefi.FVFileTypePad:                true,
		// uefi.FVFileTypeFFSMin:             true, same as Pad, bug?
		uefi.FVFileTypeFFSMax: true,
	}

	r = &visitors.Remove{
		Pad: false,
	}
	commands []cmd
)

func init() {
	commands = []cmd{
		{"fv", "Read in the firmware volume named by TOS[0]", readFV},
		{"find", "Find the REs at TOS[[0]", find},
		{"ix", "Using the RE at TOS[0], create and push a []*info", ix},
		{"status", "Describe the status of the []*info at TOS[0]", status},
		{"bad", "List names which are marked for both keep and remove", bad},
		{"tag", "Tag []*info at TOS[2] with tag at TOS[1] and value TOS[0]", tag},
		{"saverom", "Write the firmware volume to a file named by TOS[0]", saverom},
		{"untag", "Remove the tag at TOS[0] for the []info at TOS[1]", untag},
		{"go", "deprecated -- do not use", dit},
		{"run", "Run the UTK command at TOS[0] with the args from the stack", run},
		{"splat", "Replace files named .*Shell.* with the file at TOS[0]", splat},
		{"clean", "Clean the image. Runs DXECLEAN script for each iteration. Leaves artifact names in a []string at TOS[0]", clean},
		// TODO: new words for forth package to move to u-root.
		{"drop", "Drop TOS[0]", drop},
		{"help", "Print a help message", help},
	}
}
func help(f forth.Forth) {
	for _, c := range commands {
		fmt.Printf("%s: %s\n", c.c, c.h)
	}
}

// saverom saves the rom somewhere useful.
func saverom(f forth.Forth) {
	n := forth.String(f)
	rom, err := os.Create(n)
	if err != nil {
		panic(err)
	}
	defer rom.Close()
	var errs []string
	for _, f := range files {
		if _, ok := f.tags[remove]; !ok {
			continue
		}
		if _, ok := f.tags[removed]; ok {
			continue
		}
		log.Printf("Try to remove %v (%v)", f.name, f.GUID)
		rp, err := visitors.FindFilePredicate(f.GUID)
		if err != nil {
			panic(err)
		}
		r.Predicate = rp
		if err := r.Run(fv); err != nil {
			errs = append(errs, fmt.Sprintf("%v", err))
		}
		if len(r.Matches) == 0 {
			panic(fmt.Sprintf("Can't happen: %v not found", f))
		}
		f.tags[removed] = "saverom"
		log.Printf("removed %v", r.Matches)
	}
	if errs != nil {
		panic(errs)
	}
	a := &visitors.Assemble{}
	if err := fv.Apply(a); err != nil {
		panic(err)
	}
	if _, err := io.Copy(rom, bytes.NewBuffer(fv.Buf())); err != nil {
		panic(err)
	}
}

func drop(f forth.Forth) {
	if !f.Empty() {
		f.Pop()
	}
}

// do two things.
// create a tmp file with things removed that can be removed.
// create a black list
// returns a []string with the two files
func dit(f forth.Forth) {
	var blist string
	var errs []string
	for _, f := range files {
		if _, ok := f.tags["k"]; ok {
			blist += f.name + "\n"
			continue
		}
		if _, ok := f.tags["r"]; !ok {
			continue
		}
		rp, err := visitors.FindFilePredicate(f.name)
		if err != nil {
			panic(err)
		}
		r := &visitors.Remove{
			Predicate: rp,
			Pad:       false,
		}
		if err := r.Run(fv); err != nil {
			errs = append(errs, fmt.Sprintf("%v", err))
		}
	}
	if errs != nil {
		f.Push(errs)
		return
	}
	bl, err := ioutil.TempFile("", "futkblacklist")
	if err != nil {
		panic(err)
	}
	defer bl.Close()
	rom, err := ioutil.TempFile("", "futkrom")
	if err != nil {
		panic(err)
	}
	defer rom.Close()
	if _, err := io.Copy(bl, bytes.NewBufferString(blist)); err != nil {
		f.Push(err)
		return
	}
	a := &visitors.Assemble{}
	if err := fv.Apply(a); err != nil {
		f.Push(err)
		return
	}
	// Can I parse my own thing?
	_, err = uefi.Parse(fv.Buf())
	if err != nil {
		panic(err)
	}
	if _, err := io.Copy(rom, bytes.NewBuffer(fv.Buf())); err != nil {
		f.Push(err)
		return
	}
	f.Push([]string{bl.Name(), rom.Name()})
}

// Find the file name.
// Help me out here. On what planet does anything as stupid as UEFI firmware volumes
// look like a good idea? Just wondering.
func name(f uefi.Firmware) (string, error) {
	var n string
	fp := func(f uefi.Firmware) bool {
		switch f := f.(type) {
		case *uefi.Section:
			if f.Type == "EFI_SECTION_USER_INTERFACE" {
				n = f.Name
				return true
			}
		}
		return false
	}
	var b bytes.Buffer
	pred := &visitors.Find{Predicate: fp, W: &b}
	if err := pred.Run(f); err != nil {
		panic(err)
	}

	return n, nil
}

func readFV(f forth.Forth) {
	n := forth.String(f)
	image, err := ioutil.ReadFile(n)
	if err != nil {
		panic(err)
	}
	fv, err = uefi.Parse(image)
	if err != nil {
		panic(err)
	}
	// Now fill in our list.
	fp, err := visitors.FindFilePredicate(".*")
	if err != nil {
		panic(err)
	}
	var b bytes.Buffer
	pred := &visitors.Find{Predicate: fp, W: &b}
	if err := pred.Run(fv); err != nil {
		panic(err)
	}
	log.Printf("Found %d things", len(pred.Matches))
	files = make(map[uefi.Firmware]*info, len(pred.Matches))
	for _, vf := range pred.Matches {
		var f *info
		var g, n string
		var t uefi.FVFileType
		switch mfile := vf.(type) {
		case *uefi.File:
			t = mfile.Header.Type
			g = fmt.Sprintf("%v", mfile.Header.GUID.String())
			nm, err := name(mfile)
			if err != nil {
				log.Printf("finding name for %v: %v (warning only)", mfile, err)
			}
			n = fmt.Sprintf("%v:%v:%v", g, t, nm)
			f = &info{
				name:  n,
				GUID:  g,
				ftype: t,
				tags:  map[string]string{},
			}
			files[vf] = f
		}
	}

	f.Push(len(files))
}

func status(f forth.Forth) {
	ff := f.Pop().([]*info)
	var ret string
	for _, f := range ff {
		ret += fmt.Sprintf("%s: res %v\n", f.name, f.tags)
	}
	f.Push(ret)
}

func tag(f forth.Forth) {
	t := forth.String(f)
	expr := forth.String(f)
	ff := f.Pop().([]*info)
	var ret []string
	for _, f := range ff {
		if v, ok := f.tags[t]; ok {
			ret = append(ret, fmt.Sprintf("%s: %s already marked by re %s", f.name, t, v))
			continue
		}
		f.tags[t] = expr
		ret = append(ret, f.name)
	}

	if ret != nil {
		f.Push(ret)
		return
	}
	f.Push("Nothing tagged")
}

func runit(args ...string) string {
	ret := fmt.Sprintf("Run %v", args)
	v, err := visitors.ParseCLI(args)
	if err != nil {
		panic(fmt.Sprintf("%v: %v", ret, err))
	}
	if err := visitors.ExecuteCLI(fv, v); err != nil {
		panic(fmt.Sprintf("%v: %v", ret, err))
	}
	return ret
}

// Just run a command in the utk "cli"
func run(f forth.Forth) {
	var args []string
	for _, a := range f.Stack() {
		args = append(args, a.(string))
	}
	f.Reset()
	f.Push(runit(args...))
}

// You can call run to do this; we keep it separate because
// it's a bit more convenient
// we can add a tag
// we like the name splat
func splat(f forth.Forth) {
	kern := forth.String(f)
	runit("replace_pe32", ".*Shell.*", kern)
	// TODO: make shell take a []Cell
	ret, err := forth.Eval(f, ".*Shell.* ix shell replaced tag\n")
	if err != nil {
		panic(err)
	}
	/*f.Push(".*Shell.*")
	ix(f)
	f.Push("shell")
	f.Push("splat")
	tag(f)
	*/
	f.Push(ret)
}

func untag(f forth.Forth) {
	t := forth.String(f)
	ff := f.Pop().([]*info)
	var ret []string
	for _, f := range ff {
		delete(f.tags, t)
		ret = append(ret, f.name)
	}
	if ret != nil {
		f.Push(ret)
		return
	}
	f.Push("nothing untagged")
}

func bad(f forth.Forth) {
	var ret []string
	for _, f := range files {
		_, keeper := f.tags[keep]
		_, remover := f.tags[remove]
		if keeper && remover {
			ret = append(ret, fmt.Sprintf("%s: marked for keep and remove: %v", f.name, f.tags))
		}
	}
	if ret != nil {
		f.Push(ret)
		return
	}
	f.Push("Nothing bad")
}

// We create a temp directory, and, starting with the current file, create files
// in a sequence, starting with 0 as the original.
func clean(f forth.Forth) {
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 512)
	signal.Notify(sigs, os.Interrupt)
	done := make(chan bool)
	go func() {
		for i := range sigs {
			fmt.Println(i)
			cancel()
			done <- true
		}
	}()
	dir, err := ioutil.TempDir("", "futk")
	if err != nil {
		panic(err)
	}
	var generation int
	script := forth.String(f)
	log.Printf("script is %v", script)
	n := filepath.Join(dir, fmt.Sprintf("%d", generation))
	f.Push(n)
	saverom(f)
	generation++
	names := []string{n}
	var xit bool
	for !xit {
		var victim *info
		// pick a candidate to remove
		// pick the LAST one we find.
		// we suspect that later ones are more likely to
		// depend on earlier ones.
		for _, f := range files {
			if _, ok := f.tags[keep]; ok {
				continue
			}
			if _, ok := f.tags[remove]; ok {
				continue
			}
			if v, ok := notouch[f.ftype]; ok && v {
				f.tags[keep] = "notouch"
				continue
			}
			victim = f
		}
		if victim == nil {
			break
		}
		victim.tags[remove] = "cleaner"
		n = filepath.Join(dir, fmt.Sprintf("%d", generation))
		f.Push(n)
		saverom(f)
		generation++
		out, err := exec.CommandContext(ctx, script, n).CombinedOutput()
		if err != nil {
			r.Undo()
			delete(victim.tags, remove)
			victim.tags[keep] = "cleaner"
			e := fmt.Sprintf("%v", err)
			if false && e != "exit status 2" {
				f.Push(names)
				f.Push(string(out))
				f.Push(err)
				return
			}
			continue
		}
		log.Printf("Removed %v", victim)
		victim.tags[removed] = "cleaner"
		names = append(names, n)
		select {
		case <-done:
			xit = true
		default:
		}
	}
	f.Push(names)
}

// Find uses the string at TOS as an RE.
// It returns with the []*info at TOS.
func find(f forth.Forth) {
	r := forth.String(f)
	re := regexp.MustCompile(r)
	var res []string
	for _, vf := range files {
		if !re.MatchString(vf.name) {
			continue
		}
		res = append(res, vf.name)
	}
	f.Push(r)
	f.Push(res)
}

func ix(f forth.Forth) {
	r := ".*"
	if len(f.Stack()) > 0 {
		r = forth.String(f)
	}
	re := regexp.MustCompile(r)
	var res []*info
	for _, vf := range files {
		if !re.MatchString(vf.name) {
			continue
		}
		res = append(res, vf)
	}
	f.Push(res)
}

func main() {
	f := forth.New()
	for _, c := range commands {
		f.Newop(c.c, c.f)
	}
	var b = make([]byte, 512)
	flag.Parse()
	// first process the args
	s, err := forth.Eval(f, strings.Join(flag.Args(), " "))
	// In the next u-root release we'll add a new type of eval
	// that won't pop the stack but for now we have to simulate it.
	if err != nil {
		log.Printf("%v", err)
	} else {
		f.Push(s)
	}
	for {
		fmt.Printf("%v", f.Stack())
		fmt.Print("OK ")
		n, err := os.Stdin.Read(b)
		if err != nil {
			if err != io.EOF {
				log.Fatal(err)
			}
			// Silently exit on EOF. It's the unix way.
			break
		}
		s, err := forth.Eval(f, string(b[:n]))
		if err != nil {
			fmt.Printf("%v\n", err)
		}
		if err == nil {
			f.Push(s)
		}
	}
}
