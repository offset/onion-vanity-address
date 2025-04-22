package vanity25519

import (
	"bytes"
	"encoding/binary"
	"math/big"

	"github.com/offset/onion-vanity-address/internal/edwards25519"
	"github.com/offset/onion-vanity-address/internal/vanity25519/field"
)

// HasPrefixBits returns a function that checks if the input has the specified prefix bits.
func HasPrefixBits(prefix []byte, bits int) func(input []byte) bool {
	if len(prefix) == 0 || len(prefix) > 32 {
		panic("invalid prefix ")
	}
	if bits <= 0 || bits > 256 || bits > len(prefix)*8 {
		panic("invalid bits")
	}

	if bits%8 == 0 {
		return func(b []byte) bool {
			return bytes.HasPrefix(b, prefix)
		}
	}

	prefixBytes := bits / 8
	shift := 8 - (bits % 8)
	tailByte := prefix[prefixBytes] >> shift
	prefix = prefix[:prefixBytes]

	return func(b []byte) bool {
		return len(b) > prefixBytes && // must be long enough to check tail byte
			bytes.Equal(b[:prefixBytes], prefix) &&
			b[prefixBytes]>>shift == tailByte
	}
}

func scalarFromBigInt(n *big.Int) *edwards25519.Scalar {
	var buf [64]byte
	copy(buf[:], bigIntBytes(n))

	xs, err := edwards25519.NewScalar().SetUniformBytes(buf[:])
	if err != nil {
		panic(err)
	}
	return xs
}

func fieldElementFromUint64(n uint64) *field.Element {
	var nb [8]byte
	binary.LittleEndian.PutUint64(nb[:], n)
	return fieldElementFromBytes(nb[:])
}

func fieldElementFromString(s string) *field.Element {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid fieldElement string")
	}
	return fieldElementFromBigInt(n)
}

func fieldElementFromBigInt(n *big.Int) *field.Element {
	return fieldElementFromBytes(bigIntBytes(n))
}

func fieldElementFromBytes(x []byte) *field.Element {
	var buf [32]byte
	copy(buf[:], x)
	fe, err := new(field.Element).SetBytes(buf[:])
	if err != nil {
		panic(err)
	}
	return fe
}

func bigIntBytes(n *big.Int) []byte {
	if n == nil || n.Sign() < 0 {
		panic("n must be non-negative")
	}
	if n.BitLen() > 255 {
		panic("n must be less than 2^255")
	}
	var buf [32]byte
	return reverse(n.FillBytes(buf[:]))
}

func reverse(b []byte) []byte {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}
