package field

import (
	"encoding/hex"
	"math/bits"
	mathrand "math/rand"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/offset/onion-vanity-address/internal/vanity25519/internal/assert"
)

// quickCheckConfig returns a quick.Config that scales the max count by the
// given factor if the -short flag is not set.
func quickCheckConfig(slowScale int) *quick.Config {
	cfg := new(quick.Config)
	if !testing.Short() {
		cfg.MaxCountScale = float64(slowScale)
	}
	return cfg
}

func generateFieldElement(rand *mathrand.Rand) Element {
	const maskLow63Bits = (1 << 63) - 1
	return Element{
		rand.Uint64(),
		rand.Uint64(),
		rand.Uint64(),
		rand.Uint64() & maskLow63Bits,
	}
}

func (Element) Generate(rand *mathrand.Rand, size int) reflect.Value {
	return reflect.ValueOf(generateFieldElement(rand))
}

// isInBounds returns whether the element is within the expected bit size bounds.
func isInBounds(x *Element) bool {
	return bits.Len64(x.l0) <= 64 &&
		bits.Len64(x.l1) <= 64 &&
		bits.Len64(x.l2) <= 64 &&
		bits.Len64(x.l3) <= 63
}

func TestAdd(t *testing.T) {
	x := new(Element).One()
	y := new(Element).Add(x, x)

	for range 10 {
		x.Add(x, y)
	}

	assert.Equal(t, uint64(21), x.l0)
	assert.Equal(t, uint64(0), x.l1)
	assert.Equal(t, uint64(0), x.l2)
	assert.Equal(t, uint64(0), x.l3)
}

func TestSubtract(t *testing.T) {
	x := new(Element).One()
	y := new(Element).Add(x, x)

	for range 10 {
		x.Subtract(x, y)
	}

	assert.Equal(t, uint64(1<<64-19-19), x.l0)
	assert.Equal(t, uint64(1<<64-1), x.l1)
	assert.Equal(t, uint64(1<<64-1), x.l2)
	assert.Equal(t, uint64(1<<63-1), x.l3)
}

func TestMultiply(t *testing.T) {
	x := new(Element).One()
	y := new(Element).Add(x, x)

	for range 10 {
		x.Multiply(x, y)
	}

	assert.Equal(t, uint64(1024), x.l0)
	assert.Equal(t, uint64(0), x.l1)
	assert.Equal(t, uint64(0), x.l2)
	assert.Equal(t, uint64(0), x.l3)
}

func TestSquare(t *testing.T) {
	x := new(Element).Add(feOne, feOne)

	for range 3 {
		x.Square(x)
	}

	assert.Equal(t, uint64(256), x.l0)
	assert.Equal(t, uint64(0), x.l1)
	assert.Equal(t, uint64(0), x.l2)
	assert.Equal(t, uint64(0), x.l3)
}

func TestMultiplyDistributesOverAdd(t *testing.T) {
	multiplyDistributesOverAdd := func(x, y, z Element) bool {
		// Compute t1 = (x+y)*z
		t1 := new(Element)
		t1.Add(&x, &y)
		t1.Multiply(t1, &z)

		// Compute t2 = x*z + y*z
		t2 := new(Element)
		t3 := new(Element)
		t2.Multiply(&x, &z)
		t3.Multiply(&y, &z)
		t2.Add(t2, t3)

		return t1.Equal(t2) == 1 && isInBounds(t1) && isInBounds(t2)
	}

	err := quick.Check(multiplyDistributesOverAdd, quickCheckConfig(1024))
	assert.NoError(t, err)
}

func TestSqrtRatio(t *testing.T) {
	// From draft-irtf-cfrg-ristretto255-decaf448-00, Appendix A.4.
	type test struct {
		u, v      string
		wasSquare int
		r         string
	}
	tests := []test{
		// If u is 0, the function is defined to return (0, TRUE), even if v
		// is zero. Note that where used in this package, the denominator v
		// is never zero.
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000000",
			1, "0000000000000000000000000000000000000000000000000000000000000000",
		},
		// 0/1 == 0²
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0100000000000000000000000000000000000000000000000000000000000000",
			1, "0000000000000000000000000000000000000000000000000000000000000000",
		},
		// If u is non-zero and v is zero, defined to return (0, FALSE).
		{
			"0100000000000000000000000000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000000",
			0, "0000000000000000000000000000000000000000000000000000000000000000",
		},
		// 2/1 is not square in this field.
		{
			"0200000000000000000000000000000000000000000000000000000000000000",
			"0100000000000000000000000000000000000000000000000000000000000000",
			0, "3c5ff1b5d8e4113b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54",
		},
		// 4/1 == 2²
		{
			"0400000000000000000000000000000000000000000000000000000000000000",
			"0100000000000000000000000000000000000000000000000000000000000000",
			1, "0200000000000000000000000000000000000000000000000000000000000000",
		},
		// 1/4 == (2⁻¹)² == (2^(p-2))² per Euler's theorem
		{
			"0100000000000000000000000000000000000000000000000000000000000000",
			"0400000000000000000000000000000000000000000000000000000000000000",
			1, "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
		},
	}

	for i, tt := range tests {
		u, _ := new(Element).SetBytes(decodeHex(tt.u))
		v, _ := new(Element).SetBytes(decodeHex(tt.v))
		want, _ := new(Element).SetBytes(decodeHex(tt.r))
		got, wasSquare := new(Element).SqrtRatio(u, v)
		if got.Equal(want) == 0 || wasSquare != tt.wasSquare {
			t.Errorf("%d: got (%v, %v), want (%v, %v)", i, got, wasSquare, want, tt.wasSquare)
		}
	}
}

func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func BenchmarkAdd(b *testing.B) {
	x := new(Element).One()
	y := new(Element).Add(x, x)

	b.ResetTimer()
	for range b.N {
		x.Add(x, y)
	}
}

func BenchmarkSubtract(b *testing.B) {
	x := new(Element).One()
	y := new(Element).Add(x, x)

	b.ResetTimer()
	for range b.N {
		x.Subtract(x, y)
	}
}

func BenchmarkMultiply(b *testing.B) {
	x := new(Element).One()
	y := new(Element).Add(x, x)

	b.ResetTimer()
	for range b.N {
		x.Multiply(x, y)
	}
}

var z Element

func BenchmarkMultiplyNoAlias(b *testing.B) {
	x := new(Element).One()
	y := new(Element).Add(x, x)

	b.ResetTimer()
	for range b.N {
		z.Multiply(x, y)
	}
}

func BenchmarkMultiplyParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		x := new(Element).One()
		y := new(Element).Add(x, x)
		for pb.Next() {
			x.Multiply(x, y)
		}
	})
}

func BenchmarkSquare(b *testing.B) {
	x := new(Element).Add(feOne, feOne)

	b.ResetTimer()
	for range b.N {
		x.Square(x)
	}
}
