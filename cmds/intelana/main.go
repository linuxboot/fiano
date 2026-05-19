package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	fit "github.com/linuxboot/fiano/pkg/intel/metadata/fit"
	"github.com/linuxboot/fiano/pkg/uefi"
)

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) > 0 {
		path := args[0]
		data, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("\n== IFD ==\n")
		regions := [...]uefi.FlashRegionType{
			uefi.RegionTypeBIOS,
			uefi.RegionTypeME,
			uefi.RegionTypeGBE,
			uefi.RegionTypePTT,
			uefi.RegionTypeEC,
			uefi.RegionTypeMicrocode,
		}

		fi, err := uefi.NewFlashImage(data)
		if fi != nil {
			for _, r := range regions {
				if fi.IFD.Region.FlashRegions[r].Valid() {
					offset := fi.IFD.Region.FlashRegions[r].BaseOffset()
					size := fi.IFD.Region.FlashRegions[r].EndOffset() - offset
					fmt.Printf("%-9s offset %x size %x\n", r, offset, size)
				} else {
					fmt.Printf("%-9s region not found/invalid\n", r)
				}
			}
		}

		fmt.Printf("\n== FIT ==\n")
		table, err := fit.GetTable(data)
		doJson := false
		if doJson {
			j, err := json.MarshalIndent(table, "", "  ")
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf(string(j))
		} else {
			fmt.Printf("\n%s", table)
		}
	}
}
