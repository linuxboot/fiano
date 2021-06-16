//go:generate manifestcodegen

package manifest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)

// Key is a public key of an asymmetric crypto keypair.
type Key struct {
	KeyAlg  Algorithm `json:"keyAlg"`
	Version uint8     `require:"0x10"  json:"keyVersion"`
	KeySize BitSize   `json:"keyBitsize"`
	Data    []byte    `countValue:"keyDataSize()" json:"keyData"`
}

// BitSize is a size in bits.
type BitSize uint16

// InBits returns the size in bits.
func (ks BitSize) InBits() uint16 {
	return uint16(ks)
}

// InBytes returns the size in bytes.
func (ks BitSize) InBytes() uint16 {
	return uint16(ks >> 3)
}

// SetInBits sets the size in bits.
func (ks *BitSize) SetInBits(amountOfBits uint16) {
	*ks = BitSize(amountOfBits)
}

// SetInBytes sets the size in bytes.
func (ks *BitSize) SetInBytes(amountOfBytes uint16) {
	*ks = BitSize(amountOfBytes << 3)
}

// keyDataSize returns the expected length of Data for specified
// KeyAlg and KeySize.
func (k Key) keyDataSize() int64 {
	switch k.KeyAlg {
	case AlgRSA:
		return int64(k.KeySize.InBytes()) + 4
	case AlgECC, AlgSM2:
		return int64(k.KeySize.InBytes()) * 2
	}
	return -1
}

// PubKey parses Data into crypto.PublicKey.
func (k Key) PubKey() (crypto.PublicKey, error) {
	expectedSize := int(k.keyDataSize())
	if expectedSize < 0 {
		return nil, fmt.Errorf("unexpected algorithm: %s", k.KeyAlg)
	}
	if len(k.Data) != expectedSize {
		return nil, fmt.Errorf("unexpected size: expected:%d, received %d", expectedSize, len(k.Data))
	}

	switch k.KeyAlg {
	case AlgRSA:
		result := &rsa.PublicKey{
			N: new(big.Int).SetBytes(reverseBytes(k.Data[4:])),
			E: int(binaryOrder.Uint32(k.Data)),
		}
		return result, nil
	case AlgECC:
		keySize := k.KeySize.InBytes()
		x := new(big.Int).SetBytes(reverseBytes(k.Data[:keySize]))
		y := new(big.Int).SetBytes(reverseBytes(k.Data[keySize:]))
		return ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	case AlgSM2:
		keySize := k.KeySize.InBytes()
		x := new(big.Int).SetBytes(reverseBytes(k.Data[:keySize]))
		y := new(big.Int).SetBytes(reverseBytes(k.Data[keySize:]))
		return sm2.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	}

	return nil, fmt.Errorf("unexpected TPM algorithm: %s", k.KeyAlg)
}

func reverseBytes(b []byte) []byte {
	r := make([]byte, len(b))
	for idx := range b {
		r[idx] = b[len(b)-idx-1]
	}
	return r
}

// SetPubKey sets Data the value corresponding to passed `key`.
func (k *Key) SetPubKey(key crypto.PublicKey) error {
	k.Version = 0x10

	switch key := key.(type) {
	case *rsa.PublicKey:
		k.KeyAlg = AlgRSA
		n := key.N.Bytes()
		k.KeySize.SetInBytes(uint16(len(n)))
		k.Data = make([]byte, 4+len(n))
		binaryOrder.PutUint32(k.Data, uint32(key.E))
		copy(k.Data[4:], reverseBytes(n))
		return nil

	case *ecdsa.PublicKey:
		var x, y *big.Int
		k.KeyAlg = AlgECC
		x, y = key.X, key.Y
		if x == nil || y == nil {
			return fmt.Errorf("the pubkey '%#+v' is invalid: x == nil || y == nil", key)
		}
		k.KeySize.SetInBits(256)
		xB, yB := x.Bytes(), y.Bytes()
		if len(xB) != int(k.KeySize.InBytes()) || len(yB) != int(k.KeySize.InBytes()) {
			return fmt.Errorf("the pubkey '%#+v' is invalid: len(x)<%d> != %d || len(y)<%d> == %d",
				key, len(xB), int(k.KeySize.InBytes()), len(yB), int(k.KeySize.InBytes()))
		}
		k.Data = make([]byte, 2*k.KeySize.InBytes())
		copy(k.Data[:], reverseBytes(xB))
		copy(k.Data[len(xB):], reverseBytes(yB))
		return nil

	case *sm2.PublicKey:
		var x, y *big.Int
		k.KeyAlg = AlgSM2
		x, y = key.X, key.Y
		if x == nil || y == nil {
			return fmt.Errorf("the pubkey '%#+v' is invalid: x == nil || y == nil", key)
		}
		k.KeySize.SetInBits(256)
		xB, yB := x.Bytes(), y.Bytes()
		if len(xB) != int(k.KeySize.InBytes()) || len(yB) != int(k.KeySize.InBytes()) {
			return fmt.Errorf("the pubkey '%#+v' is invalid: len(x)<%d> != %d || len(y)<%d> == %d",
				key, len(xB), int(k.KeySize.InBytes()), len(yB), int(k.KeySize.InBytes()))
		}
		k.Data = make([]byte, 2*k.KeySize.InBytes())
		copy(k.Data[:], reverseBytes(xB))
		copy(k.Data[len(xB):], reverseBytes(yB))
		return nil
	}

	return fmt.Errorf("unexpected key type: %T", key)
}

//PrintBPMPubKey prints the BPM public signing key hash to fuse into the Intel ME
func (k *Key) PrintBPMPubKey(bpmAlg Algorithm) error {
	buf := new(bytes.Buffer)
	if len(k.Data) > 1 {
		hash, err := bpmAlg.Hash()
		if err != nil {
			return err
		}
		if k.KeyAlg == AlgRSA {
			if err := binary.Write(buf, binary.LittleEndian, k.Data[4:]); err != nil {
				return err
			}
			hash.Write(buf.Bytes())
			fmt.Printf("   Boot Policy Manifest Pubkey Hash: 0x%x\n", hash.Sum(nil))
		} else if k.KeyAlg == AlgSM2 || k.KeyAlg == AlgECC {
			if err := binary.Write(buf, binary.LittleEndian, k.Data); err != nil {
				return err
			}
			hash.Write(buf.Bytes())
			fmt.Printf("   Boot Policy Manifest Pubkey Hash: 0x%x\n", hash.Sum(nil))
		} else {
			fmt.Printf("   Boot Policy Manifest Pubkey Hash: Unknown Algorithm\n")
		}
	} else {
		fmt.Printf("   Boot Policy Pubkey Hash: No km public key set in KM\n")
	}

	return nil
}

//PrintKMPubKey prints the KM public signing key hash to fuse into the Intel ME
func (k *Key) PrintKMPubKey(kmAlg Algorithm) error {
	buf := new(bytes.Buffer)
	if len(k.Data) > 1 {
		if k.KeyAlg == AlgRSA {
			if err := binary.Write(buf, binary.LittleEndian, k.Data[4:]); err != nil {
				return err
			}
			if err := binary.Write(buf, binary.LittleEndian, k.Data[:4]); err != nil {
				return err
			}
			if kmAlg != AlgSHA256 {
				return fmt.Errorf("KM public key hash algorithm must be SHA256")
			}
			hash, err := kmAlg.Hash()
			if err != nil {
				return err
			}
			hash.Write(buf.Bytes())
			fmt.Printf("   Key Manifest Pubkey Hash: 0x%x\n", hash.Sum(nil))
			// On SKL and KBL the exponent is not included in the KM hash
			buf.Truncate(len(k.Data[4:]))
			hash.Reset()
			hash.Write(buf.Bytes())
			fmt.Printf("   Key Manifest Pubkey Hash (Skylake and Kabylake only): 0x%x\n", hash.Sum(nil))
		} else {
			fmt.Printf("   Key Manifest Pubkey Hash: Unsupported Algorithm\n")
		}
	} else {
		fmt.Printf("   Key Manifest Pubkey Hash: No km public key set in KM\n")
	}

	return nil
}
