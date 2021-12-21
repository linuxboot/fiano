//go:generate manifestcodegen

package manifest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// Key is a public key of an asymmetric crypto keypair.
type Key struct {
	KeyAlg  tpm2.Algorithm `json:"key_alg"`
	Version uint8          `require:"0x10"  json:"key_version"`
	KeySize BitSize        `json:"key_bitsize"`
	Data    []byte         `countValue:"keyDataSize()" json:"key_data"`
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
	case tpm2.AlgRSA:
		return int64(k.KeySize.InBytes()) + 4
	case tpm2.AlgECC:
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
	case tpm2.AlgRSA:
		result := &rsa.PublicKey{
			N: new(big.Int).SetBytes(reverseBytes(k.Data[4:])),
			E: int(binaryOrder.Uint32(k.Data)),
		}

		return result, nil
	case tpm2.AlgECC:
		keySize := k.KeySize.InBytes()
		x := new(big.Int).SetBytes(reverseBytes(k.Data[:keySize]))
		y := new(big.Int).SetBytes(reverseBytes(k.Data[keySize:]))
		return ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
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
		k.KeyAlg = tpm2.AlgRSA
		n := key.N.Bytes()
		k.KeySize.SetInBytes(uint16(len(n)))
		k.Data = make([]byte, 4+len(n))
		binaryOrder.PutUint32(k.Data, uint32(key.E))
		copy(k.Data[4:], reverseBytes(n))
		return nil

	case *ecdsa.PublicKey:
		var x, y *big.Int
		k.KeyAlg = tpm2.AlgRSA
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

//PrintMEKey prints the KM public signing key hash to fuse into the Intel ME
func (k *Key) PrintMEKey() error {
	buf := new(bytes.Buffer)
	if len(k.Data) > 1 {
		if err := binary.Write(buf, binary.LittleEndian, k.Data[4:]); err != nil {
			return nil
		}
		if err := binary.Write(buf, binary.LittleEndian, k.Data[:4]); err != nil {
			return nil
		}
		h := sha256.New()
		h.Write(buf.Bytes())
		fmt.Printf("   Key Manifest Pubkey Hash: 0x%x\n", h.Sum(nil))
	} else {
		fmt.Printf("   Key Manifest Pubkey Hash: No km public key set in KM\n")
	}

	return nil
}
