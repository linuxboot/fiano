// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"time"

	"9fans.net/go/draw"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// Display the memory map with used areas in red.
// This can be called multiple times.
// The argument is the display name.
type Display struct {
	// Input
	Predicate func(f uefi.Firmware) bool
	Name      string
	// logs are written to this writer.
	W io.Writer
}

func (v *Display) printf(format string, a ...interface{}) {
	if v.W != nil {
		fmt.Fprintf(v.W, format, a...)
	}
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Display) Run(f uefi.Firmware) error {
	return f.Apply(v)
}

// Visit applies the Display visitor to any Firmware type.
// The name "end" has meaning. It will force an assemble of the image,
// which should cleanup f.Buf(), and it will not return.
// If it returns, utk will exit and you will see no images.
// Using "end" this way lets us hold off on using goroutines and
// waitgroups for now.
func (v *Display) Visit(f uefi.Firmware) error {
	switch f := f.(type) {
	case *uefi.BIOSRegion:
		if v.Name != "start" {
			// If we are not the first display
			// Assemble the binary to make sure the top level buffer is correct
			if err := (&Assemble{}).Run(f); err != nil {
				return err
			}
		}

		b := bytes.NewBuffer(f.Buf())
		os.WriteFile(v.Name, f.Buf(), 0644)
		numblocks := b.Len()/uefi.RegionBlockSize
		// The display is 256 blocks x however many rows we need.
		// So that's len(buf) / (256x1024)
		squareSize := 2
		wid := 256*squareSize
		ht := squareSize*(numblocks/256)
		// Initialize the draw context with a dynamically-sized window
		d, err := draw.Init(nil, "", v.Name, fmt.Sprintf("%dx%d", wid+50, ht+20))
		if err != nil {
			return fmt.Errorf("failed to initialize draw: %w", err)
		}

		// Initialize mouse control using drawfcall
		//	mousectl, err := drawfcall.InitMouse("", d.ScreenImage)
		//if err != nil {
		//log.Fatalf("failed to initialize mouse: %v", err)
		//}

		// Determine the window size from the screen image
		winWidth := wid
		winHeight := ht

		// Get color images for red and green
		grn := d.AllocImageMix(draw.Green, draw.Opaque)
		red := d.AllocImageMix(draw.Red, draw.Opaque)

		var buf [uefi.RegionBlockSize]byte
		done:
		for y := 0; y < winHeight; y++ {
			for x := 0; x < winWidth; x++ {
				// Calculate the top-left corner of the square
				pt := draw.Pt(20+x*squareSize, 20+y*squareSize)
				rect := draw.Rect(pt.X, pt.Y, pt.X+squareSize, pt.Y+squareSize)
				n, err := b.Read(buf[:])
				if err != nil && err != io.EOF {
					return fmt.Errorf("reading buffer with non-eof error:%w", err)
				}
				if n == 0 {
					break done
				}

				// Alternate colors between red and yellow
				if uefi.IsErased(buf[:n], uefi.Attributes.ErasePolarity) {
					d.ScreenImage.Draw(rect, grn, nil, draw.ZP)
				} else {
					d.ScreenImage.Draw(rect, red, nil, draw.ZP)
				}
			}
		}

		d.Flush()

		// What a hack. But it will let us test the idea,
		// until we're sure it is right.
		for v.Name == "end" {
			time.Sleep(40 * time.Second)
		}

	}

	return nil
}

func init() {
	RegisterCLI("display", "display the memory map", 1, func(args []string) (uefi.Visitor, error) {
		if len(args) != 1 {
			return nil, fmt.Errorf("usage: display <name>:%w", os.ErrInvalid)
		}
		return &Display{
			Name: args[0],
			W:    os.Stdout,
		}, nil
	})
}
