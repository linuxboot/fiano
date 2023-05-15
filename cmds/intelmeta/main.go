// Copyright 2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/linuxboot/fiano/pkg/intel/metadata/bg/bgbootpolicy"
	"github.com/linuxboot/fiano/pkg/intel/metadata/bg/bgkey"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntbootpolicy"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntkey"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
	"github.com/linuxboot/fiano/pkg/log"
)

var (
	flagJSON = flag.Bool("j", false, "Output as JSON")
)

func getLeakedKeys() ([10][]byte, error) {
	var keys = [10]string{
		// https://github.com/binarly-io/SupplyChainAttacks/blob/main/MSI/MsiImpactedDevices.md
		"77304b5179d0924e55060188495c80135da6be5a357234809e04a50c9629be6832f2d71be5e720a71bc9103b62413f91f98bf35723a358c5a24530fd46f6c89e6b3c22b77cd364b252bb0190cbc5ef6dd91811bfeff9a7308a6b5d60a4297dcfab6302d5d9db78103d4467d097bacce456b54c983f175c44bfd150b5121a589fa642308fd522471b6216afa0a9dbf8f158b0f7a787c0c6a58e70f2ebbff73708a880ae929bdc6097d6bc6463ab524c4ee6e9aa208ac845211b0e04fe8f2dca3799641af550e4740498ed7c3b4e9ceaf8e9256a30623cba4799ba8198cb3d53e28492c49ce3512856dfd4577992c6c7867eee353bbb38424ac83dcfc7dfba902bb41b180ded8026ac9591f3575cc4e2a6e228c4f12e978996984cb48bfd982067c00baa789447f56d63f52f4bc210025b239b92141592eb0734088647c14ff3df646bd0e629ccb0ec57bec4372700d1041cdd44ecf4e4067cc363e76af1d52fbffc8a6164b25d4c7611b57169c76717a940f387959916aa259a1064596bbc76a7",
		"af3a5bee87e8cfa1bc040c7dab318d74278c453f7fc750e1f9de642bb1e467dd36f84f548acb4270a58bdbcb54584c55a60466ea54d34053de06526ff32f1aafd1d8c4c92dae8d2bb097e7d36de9f0b41431de36e543386dbc6c8f674195bd8f5b6d0b39546c728e76075127d27adb1dc1d9e4ead47aae51812ba7655136d5be5b670f083505c5eec58ff77892e519220ab579bfdd7031d2a7f9534279424901cffe30ee1e585ba3e1f5faa8e5ad99f39fa87f27c39b854abcf3e0b7f6330439ce82074beb1d0b90ad13bf29463695cea80d5e1deb12ac58c946deac0de5393258dd545bd9fbf5fb55a052a7c2fcc181af9595fff110248e2eb1814cddf5fb6f8765019c6eb21bfa2b5e3826ec801cd7828a831cdcbdc8b3479b4109e86421af509b9c15bea0dd52af5ea5320258f326bf8116cf1a665f96a30eec72e9c75a1972f3b28b83a0060b8fd819fc898a967580c3ce027b6c3fa94ec7dfe125973a9a275762bbc799ff2d8184974de74cce78cb530f6009432e951dbf37d5ac966abb",
		"b54d2b7c8a5be3023b7de2a7e75b2b8e927359c893c4977027f957f6ac7c580f78fec3eae65b7a34915bb2029404fba8c562ffe193fc2a469e995ff947f23029ccd8bea9843fe28901ebc1ac99f0a2be6284257248b213e4d83f755ac29faa1bf22d1eee0ff04f7645b87c66aecb6253c094a0bcf4b305d8567b6d5a80daf2b720ea966a198b6830095fac5ec386537b0dee6d222225abebdadd15a991080429566ae3b132c6678ad0697d0045d389cef8e965ebc2a165ce37311cb2bbf57512ac7aedfee9266b20b0d767992a0d6cae757793e058a24ead0d0335aa2b0118b8db60cfceb2c737706e62c6b4ac98a676c52150762659a2ca60125d774ac40413120477501fb18155619cc14fddef8e322f3a9fffdbeefaa4989043890d1f1bc67a9bc7657a5cc409435daf84fd39776e62ee583778f12062ab613aeaf6e62b32b415759cbc93c223fb45b8c87c9f0bf1bd9e749858350c4c7c26cf6c7e6d9ca1fd6d56d66450feb38ce3a25aa44c1bdc978641e02affb76cba8684a326845bdd",
		"fdc427b39f77949c8c657a09484ee2fda4378cbece0d3651202e4fa62d0cf7916b9ae0592d1d8687f312406fc7e37504a80740eddf788a20a4d2ad3fad9105956ac27ed48e60acef4cc70092348676649e44b371772ca1a5225dd966ca955a5a8dd713c1ed31876f3846b1efce5734d7833ee3db9acb4c123cf3a79be142aa97603ba853d4cbe44c14bb10db27233a7db7fe5e57d3ea34cd9a6413d0d33dbf569238d314f9f3c7e93372cd6554ce15126ff4aa3819b4b28a645fa8fc4186110ddc1bc4dcc6bf11ecec639976424459bc6f817ae4364002062a59e3509b928f2b659b193b6f453f68ea82863ea2b2de1f4c19324d217e4830a6dd2cebd6192aaf646e3066e3991346428ef834fa06897446d9b507a6035cb8067e7ab3d621c012566d687748e60dcd0782772dcb805fc55c4b83d9c12b0e43c03583f894b51453f5fcaa16ba54abf90e8bb6e49b4999727228f4c437aef223e34964e30ab360357282d8187b4cf8a36a946ab35540df41f2f45ea8a00e64603da4fa2b56ba4bdd",
		// https://github.com/binarly-io/SupplyChainAttacks/blob/main/Lenovo:LCFC/IntelKeysImpactedDevices.md
		"53450ff591470c7dc3d7430b3f99780d3d6c87b54b32224d6a1ca88394c4c0831393d9d6bd5f9c2c2edf86959caaa36917c05ef42b9e0fc16c966e0fdf968014fe51a7886313ea804815d5ed249e7dfe177c518c023b280fcf62d713e04895fc3be67c5fdee26fd3f502a60c8be9ccadefe632d53807ee7e67875905239bc88b84c02faa4e095c778e5087794ec6c36f39f950c8935ca62c4c2e3f2ac3025a9c6d0d4e3e5b3cf85dc78dafc7eaadcd2f1337ff4f8cf3fae48bc7b631e464a923dd1f602f17a22289c2f4ec5657289d801831eec84cf8a79087e47a7afbf3f085ae42b054d4a3fd2c4f87827946ea4fa24581b7cd7633496e5db89385a947e2c07b24eb7fd9bda266f6abe60789e1deee1a27c9cc33cb86e0a62ad8e5fcf2a0cc52368bc73b2dc209cf2a6ad380e597dec884051af8883042675d95617a8b9902446948e896c1a1375b64fbce46f0b3927f77d1b1b6b3d6e0069df307afc7e6d60e113996038c348bbf0ea8dab5025a61a140349957e8a00589a6e7b9cb5043e3",
		"13158420e2d1fb847e49a7994df957efdfcc975b8238aa2191e98c24620db163b9d34ba8f1e96b408ec8173291324c25ade38a3f2c77081e4f19550112fb5c9055e2e57642ecc0411fe7ec965f1eab8f9c24d62690a84e3a51e514931c86049b6574438d997c79503136e9979192c66ba8aa4f7db77a760fba352174b6048bf5a0820c0b3087e32f75d72ef27ddc70e8b2807d39f1c49140ec125e7a445cc722c7809e563f990935ce33f8e4b25c4433fdd73d31ec2136fd1206f19678cbcea8b64c58c2b7a8ddea5daee54a289b5f6c8ab8f8698d977a241cbf74c5b102ea0e650bd0d5405f6bdc9bcfec40d1dd6af2c7294eb880a16bcf8e3b1c284069e0e4",
		"ff849b32ff8a956b5949868d619101651a35ae51182a8f550592a82ff14e96403f35c2fad403c8f91310f0e4adcf747c62a0805d40d8802e474024dffd02288991086ad818afb83a967dbee073a94b20fa095751e6be3d4378c99429f5af93b1b303a5886bc7d728f451eff0f23a0af9812eb6c55b9b1275faebd16acedb9f52b08a5ce7802e0971126fa6910ace7a70b13284e9a12e3f4f953de93ec0b1941a2b7e6f47c714e2d5cb481a4230c8b8032815183aa32e5b1997145063176dda642485c271649d6fe2900760b527c86f516de73f5c777a29aa54173a2f3b51d0713c4f4c8ceeb8b0bc3869d5aba0743796d8f65001371eea7bb1a1472d67ce5dbf",
		"ddd5d1efba0b586e933c3dfbf7aa84deaba6716c57747c517b8243884f0fa5dc57ebb2ede50c1f3dfe5b07c9c32c8f463fcb73856674b7996df5673666be1a4e989084f3a519b03f1a4ad2975166ff4c75097f300b328fd61e879a38fbf341c1b34f896b1a82dfc51bb2857d64a8e052621ef57ed6a9e6d3939fe968826ddc69e2a12e293a569fd5043ce33bb0926979fa24071bb174858d941f50390fdbc414fd4669434c76419978dd019b0c5496377641cccf13675ac573db0e525c47d4c875ed8a7374f325609f7c571a95e9ea0d144fadcfd6a57c013b9daeddd06e156831fca833e8b3fd941b280d595589427f9a3e331e9f47b15027be6c960f82feca",
		"d903fc44ebad1579bfb1a54522f2afa86ebdb862f54b59fe6b97a69af0745989e2352700747e8b10dfef1584d0d9a777e8aff37ede4a2a1a185f50ed01b74da4bdb465a57488108a22f6b0c6e6a1ba645ed85e8ffc9137effa886656401d9a604391dc0b6d8b01284a5b4db71ffc0f798e92b4030b02b83b16bad3a7f47072d84ee7c00c5257b10574c724d26bc6b75aba356e810fca0c46cf8fbbf48dfc5b3d8559b0357b30c2104e933c6ecc66cc2dd14f5a5ece734c2578f1734ce2253325189c639b21581fc56faa4036582578a4a86dc5ca5f9511d2036e00fa74619d2b1816410a3ccf84e8bbb4a776d3d9862b4268f31e31314ead28ecf66653e5269fc6fa396d1704bf5bd33e55240eb11f2090608d97c5b3b7eddc9f469f2f625d10e980e84ccc0d64e01ab211d6034424aa411407280de3a8a6e7271723658846ed9bde9ac237e22f4f143d322ae20e2c41367ad69bf1a4ea8d26a9a885f0566900658847ca3b7d17f67be9cb5a49398b41f0f65bd01130c892c89851afc64a76d8",
	}

	var bkeys [10][]byte
	var err error

	for i, k := range keys {
		bkeys[i], err = hex.DecodeString(k)
		if err != nil {
			return bkeys, err
		}
	}

	return bkeys, nil
}

type Manifest interface{}

type Meta struct {
	Keym      Manifest
	Polm      Manifest
	Fit       []fit.Entry
	LeakedKey string
}

func main() {
	flag.Parse()
	if flag.Arg(0) == "" {
		log.Fatalf("missing file name")
	}
	filePath := flag.Arg(0)
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("cannot read input file: %v", err)
	}

	entries, err := fit.GetEntries(data)
	if err != nil {
		log.Fatalf("cannot parse input file: %v", err)
	}

	var bme fit.Entry
	var kme fit.Entry
	for idx, entry := range entries {
		// if entry.GetEntryBase().Headers.Type() == fit.EntryTypeStartupACModuleEntry {
		if entry.GetEntryBase().Headers.Type() == fit.EntryTypeKeyManifestRecord {
			kme = entry
			fmt.Fprintf(os.Stderr, "key manifest @ %v\n", idx)
		}
		if entry.GetEntryBase().Headers.Type() == fit.EntryTypeBootPolicyManifest {
			bme = entry
			fmt.Fprintf(os.Stderr, "boot policy manifest @ %v\n", idx)
		}
	}

	var meta Meta
	meta.Fit = entries

	if bme == nil {
		fmt.Fprintf(os.Stderr, "no boot manifest entry\n")
	} else {
		bpm := bgbootpolicy.Manifest{}
		_, err = bpm.ReadFrom(bytes.NewReader(bme.GetEntryBase().DataSegmentBytes))
		if err == nil {
			if !*flagJSON {
				fmt.Print(bpm.PrettyString(0, true))
			}
			meta.Polm = bpm
		} else {
			// log.Fatalf("%v", err)
			bpm := cbntbootpolicy.Manifest{}
			_, err = bpm.ReadFrom(bytes.NewReader(bme.GetEntryBase().DataSegmentBytes))
			if err == nil {
				if !*flagJSON {
					fmt.Print(bpm.PrettyString(0, true))
				}
				meta.Polm = bpm
			} else {
				// log.Fatalf("%v", err)
			}
		}
	}

	if kme == nil {
		fmt.Fprintf(os.Stderr, "no key manifest entry\n")
	} else {
		km := bgkey.Manifest{}
		_, err = km.ReadFrom(bytes.NewReader(kme.GetEntryBase().DataSegmentBytes))
		if err == nil {
			if !*flagJSON {
				fmt.Print(km.PrettyString(0, true))
			}
			meta.Keym = km
		} else {
			// log.Fatalf("%v", err)
			km := cbntkey.Manifest{}
			_, err = km.ReadFrom(bytes.NewReader(kme.GetEntryBase().DataSegmentBytes))
			if err == nil {
				if !*flagJSON {
					fmt.Print(km.PrettyString(0, true))
				}
				meta.Keym = km
			} else {
				// log.Fatalf("%v", err)
			}
		}
	}

	leakedKeys, err := getLeakedKeys()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERR]: cannot decode list of presumably hex-encoded leaked keys\n")
	}
	if meta.Polm != nil {
		// https://go.dev/tour/methods/15
		_, ok := meta.Polm.(cbntbootpolicy.Manifest)
		if ok == true {
			pol := meta.Polm.(cbntbootpolicy.Manifest)
			k := pol.PMSE.Key.Data[4:]
			for _, lk := range leakedKeys {
				if bytes.Equal(k, lk) {
					meta.LeakedKey = hex.EncodeToString(lk[:8])
				}
			}
		}
		if ok == false {
			p, ok := meta.Polm.(bgbootpolicy.Manifest)
			if ok == true {
				k := p.PMSE.Key.Data[4:]
				for _, lk := range leakedKeys {
					if bytes.Equal(k, lk) {
						meta.LeakedKey = hex.EncodeToString(lk[:8])
					}
				}
			}
		}
	}

	if *flagJSON {
		j, err := json.MarshalIndent(meta, "", "  ")
		if err != nil {
			log.Fatalf("cannot marshal to JSON: %v", err)
		}
		fmt.Println(string(j))
	}

	if meta.LeakedKey != "" {
		fmt.Fprintf(os.Stderr, "LEAKED BG KEY USED: %x\n", meta.LeakedKey)
	}
}
