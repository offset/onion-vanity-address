package field

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// Element represents an element of the field GF(2^255-19).
//
// This type works similarly to [github.com/offset/onion-vanity-address/internal/edwards25519/field.Element],
// and all arguments and receivers are allowed to alias.
//
// The zero value is a valid zero element.
type Element struct {
	// An element t represents the integer
	//     t.l0 + t.l1*2^64 + t.l2*2^128 + t.l3*2^192
	l0 uint64
	l1 uint64
	l2 uint64
	l3 uint64
}

// Set sets v = a, and returns v.
func (v *Element) Set(a *Element) *Element {
	*v = *a
	return v
}

// SetBytes sets v to x, where x is a 32-byte little-endian encoding. If x is
// not of the right length, SetBytes returns nil and an error, and the
// receiver is unchanged.
//
// Consistent with RFC 7748, the most significant bit (the high bit of the
// last byte) is ignored, and non-canonical values (2^255-19 through 2^255-1)
// are accepted. Note that this is laxer than specified by RFC 8032, but
// consistent with most Ed25519 implementations.
func (v *Element) SetBytes(x []byte) (*Element, error) {
	if len(x) != 32 {
		return nil, errors.New("edwards25519: invalid field element input size")
	}

	v.l0 = binary.LittleEndian.Uint64(x[0*8:])
	v.l1 = binary.LittleEndian.Uint64(x[1*8:])
	v.l2 = binary.LittleEndian.Uint64(x[2*8:])
	v.l3 = binary.LittleEndian.Uint64(x[3*8:])
	v.l3 &= (1<<63 - 1)

	return v, nil
}

// Bytes returns the canonical 32-byte little-endian encoding of v.
func (v *Element) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [32]byte
	return v.bytes(&out)
}

// FillBytes sets buf the canonical 32-byte little-endian encoding of v, and returns buf.
// If the value of v doesn't fit in buf, FillBytes will panic.
func (v *Element) FillBytes(buf []byte) []byte {
	binary.LittleEndian.PutUint64(buf[0*8:], v.l0)
	binary.LittleEndian.PutUint64(buf[1*8:], v.l1)
	binary.LittleEndian.PutUint64(buf[2*8:], v.l2)
	binary.LittleEndian.PutUint64(buf[3*8:], v.l3)

	return buf
}

func (v *Element) bytes(out *[32]byte) []byte {
	binary.LittleEndian.PutUint64(out[0*8:], v.l0)
	binary.LittleEndian.PutUint64(out[1*8:], v.l1)
	binary.LittleEndian.PutUint64(out[2*8:], v.l2)
	binary.LittleEndian.PutUint64(out[3*8:], v.l3)

	return out[:]
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (v *Element) Equal(u *Element) int {
	su, sv := u.Bytes(), v.Bytes()
	return subtle.ConstantTimeCompare(su, sv)
}

// mask64Bits returns 0xffffffff if cond is 1, and 0 otherwise.
func mask64Bits(cond int) uint64 { return ^(uint64(cond) - 1) }

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *Element) Select(a, b *Element, cond int) *Element {
	m := mask64Bits(cond)
	v.l0 = (m & a.l0) | (^m & b.l0)
	v.l1 = (m & a.l1) | (^m & b.l1)
	v.l2 = (m & a.l2) | (^m & b.l2)
	v.l3 = (m & a.l3) | (^m & b.l3)
	return v
}

// Swap swaps v and u if cond == 1 or leaves them unchanged if cond == 0, and returns v.
func (v *Element) Swap(u *Element, cond int) {
	m := mask64Bits(cond)
	t := m & (v.l0 ^ u.l0)
	v.l0 ^= t
	u.l0 ^= t
	t = m & (v.l1 ^ u.l1)
	v.l1 ^= t
	u.l1 ^= t
	t = m & (v.l2 ^ u.l2)
	v.l2 ^= t
	u.l2 ^= t
	t = m & (v.l3 ^ u.l3)
	v.l3 ^= t
	u.l3 ^= t
}

var feZero = &Element{0, 0, 0, 0}

// Zero sets v = 0, and returns v.
func (v *Element) Zero() *Element {
	*v = *feZero
	return v
}

var feOne = &Element{1, 0, 0, 0}

// One sets v = 1, and returns v.
func (v *Element) One() *Element {
	*v = *feOne
	return v
}

// Add sets v = x + y, and returns v.
func (v *Element) Add(x, y *Element) *Element {
	bignum_add_p25519(v, x, y)
	return v
}

// Subtract sets v = a - b, and returns v.
func (v *Element) Subtract(a, b *Element) *Element {
	bignum_sub_p25519(v, a, b)
	return v
}

// Multiply sets v = x * y, and returns v.
func (v *Element) Multiply(x, y *Element) *Element {
	bignum_mul_p25519(v, x, y)
	return v
}

// Square sets v = x * x, and returns v.
func (v *Element) Square(x *Element) *Element {
	bignum_sqr_p25519(v, x)
	return v
}

// Negate sets v = -a, and returns v.
func (v *Element) Negate(a *Element) *Element {
	return v.Subtract(feZero, a)
}

// IsNegative returns 1 if v is negative, and 0 otherwise.
func (v *Element) IsNegative() int {
	return int(v.Bytes()[0] & 1)
}

// Absolute sets v to |u|, and returns v.
func (v *Element) Absolute(u *Element) *Element {
	return v.Select(new(Element).Negate(u), u, u.IsNegative())
}

// Invert sets v = 1/z mod p, and returns v.
//
// If z == 0, Invert returns v = 0.
func (v *Element) Invert(z *Element) *Element {
	// Inversion is implemented as exponentiation with exponent p − 2. It uses the
	// same sequence of 254 squarings and 11 multiplications as [Curve25519].
	var z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t Element

	z2.Square(z)             // 2
	t.Square(&z2)            // 4
	t.Square(&t)             // 8
	z9.Multiply(&t, z)       // 9
	z11.Multiply(&z9, &z2)   // 11
	t.Square(&z11)           // 22
	z2_5_0.Multiply(&t, &z9) // 31 = 2^5 - 2^0

	t.Square(&z2_5_0) // 2^6 - 2^1
	for i := 0; i < 4; i++ {
		t.Square(&t) // 2^10 - 2^5
	}
	z2_10_0.Multiply(&t, &z2_5_0) // 2^10 - 2^0

	t.Square(&z2_10_0) // 2^11 - 2^1
	for i := 0; i < 9; i++ {
		t.Square(&t) // 2^20 - 2^10
	}
	z2_20_0.Multiply(&t, &z2_10_0) // 2^20 - 2^0

	t.Square(&z2_20_0) // 2^21 - 2^1
	for i := 0; i < 19; i++ {
		t.Square(&t) // 2^40 - 2^20
	}
	t.Multiply(&t, &z2_20_0) // 2^40 - 2^0

	t.Square(&t) // 2^41 - 2^1
	for i := 0; i < 9; i++ {
		t.Square(&t) // 2^50 - 2^10
	}
	z2_50_0.Multiply(&t, &z2_10_0) // 2^50 - 2^0

	t.Square(&z2_50_0) // 2^51 - 2^1
	for i := 0; i < 49; i++ {
		t.Square(&t) // 2^100 - 2^50
	}
	z2_100_0.Multiply(&t, &z2_50_0) // 2^100 - 2^0

	t.Square(&z2_100_0) // 2^101 - 2^1
	for i := 0; i < 99; i++ {
		t.Square(&t) // 2^200 - 2^100
	}
	t.Multiply(&t, &z2_100_0) // 2^200 - 2^0

	t.Square(&t) // 2^201 - 2^1
	for i := 0; i < 49; i++ {
		t.Square(&t) // 2^250 - 2^50
	}
	t.Multiply(&t, &z2_50_0) // 2^250 - 2^0

	t.Square(&t) // 2^251 - 2^1
	t.Square(&t) // 2^252 - 2^2
	t.Square(&t) // 2^253 - 2^3
	t.Square(&t) // 2^254 - 2^4
	t.Square(&t) // 2^255 - 2^5

	return v.Multiply(&t, &z11) // 2^255 - 21
}

// Mult32 sets v = x * y, and returns v.
func (v *Element) Mult32(x *Element, y uint32) *Element {
	return v.Multiply(x, &Element{uint64(y), 0, 0, 0})
}

// Pow22523 set v = x^((p-5)/8), and returns v. (p-5)/8 is 2^252-3.
func (v *Element) Pow22523(x *Element) *Element {
	var t0, t1, t2 Element

	t0.Square(x)             // x^2
	t1.Square(&t0)           // x^4
	t1.Square(&t1)           // x^8
	t1.Multiply(x, &t1)      // x^9
	t0.Multiply(&t0, &t1)    // x^11
	t0.Square(&t0)           // x^22
	t0.Multiply(&t1, &t0)    // x^31
	t1.Square(&t0)           // x^62
	for i := 1; i < 5; i++ { // x^992
		t1.Square(&t1)
	}
	t0.Multiply(&t1, &t0)     // x^1023 -> 1023 = 2^10 - 1
	t1.Square(&t0)            // 2^11 - 2
	for i := 1; i < 10; i++ { // 2^20 - 2^10
		t1.Square(&t1)
	}
	t1.Multiply(&t1, &t0)     // 2^20 - 1
	t2.Square(&t1)            // 2^21 - 2
	for i := 1; i < 20; i++ { // 2^40 - 2^20
		t2.Square(&t2)
	}
	t1.Multiply(&t2, &t1)     // 2^40 - 1
	t1.Square(&t1)            // 2^41 - 2
	for i := 1; i < 10; i++ { // 2^50 - 2^10
		t1.Square(&t1)
	}
	t0.Multiply(&t1, &t0)     // 2^50 - 1
	t1.Square(&t0)            // 2^51 - 2
	for i := 1; i < 50; i++ { // 2^100 - 2^50
		t1.Square(&t1)
	}
	t1.Multiply(&t1, &t0)      // 2^100 - 1
	t2.Square(&t1)             // 2^101 - 2
	for i := 1; i < 100; i++ { // 2^200 - 2^100
		t2.Square(&t2)
	}
	t1.Multiply(&t2, &t1)     // 2^200 - 1
	t1.Square(&t1)            // 2^201 - 2
	for i := 1; i < 50; i++ { // 2^250 - 2^50
		t1.Square(&t1)
	}
	t0.Multiply(&t1, &t0)     // 2^250 - 1
	t0.Square(&t0)            // 2^251 - 2
	t0.Square(&t0)            // 2^252 - 4
	return v.Multiply(&t0, x) // 2^252 - 3 -> x^(2^252-3)
}

// sqrtM1 is 2^((p-1)/4), which squared is equal to -1 by Euler's Criterion.
var sqrtM1 = &Element{
	l0: 14190309331451158704,
	l1: 3405592160176694392,
	l2: 3120150775007532967,
	l3: 3135389899092516619,
}

// SqrtRatio sets r to the non-negative square root of the ratio of u and v.
//
// If u/v is square, SqrtRatio returns r and 1. If u/v is not square, SqrtRatio
// sets r according to Section 4.3 of draft-irtf-cfrg-ristretto255-decaf448-00,
// and returns r and 0.
func (r *Element) SqrtRatio(u, v *Element) (R *Element, wasSquare int) {
	t0 := new(Element)

	// r = (u * v3) * (u * v7)^((p-5)/8)
	v2 := new(Element).Square(v)
	uv3 := new(Element).Multiply(u, t0.Multiply(v2, v))
	uv7 := new(Element).Multiply(uv3, t0.Square(v2))
	rr := new(Element).Multiply(uv3, t0.Pow22523(uv7))

	check := new(Element).Multiply(v, t0.Square(rr)) // check = v * r^2

	uNeg := new(Element).Negate(u)
	correctSignSqrt := check.Equal(u)
	flippedSignSqrt := check.Equal(uNeg)
	flippedSignSqrtI := check.Equal(t0.Multiply(uNeg, sqrtM1))

	rPrime := new(Element).Multiply(rr, sqrtM1) // r_prime = SQRT_M1 * r
	// r = CT_SELECT(r_prime IF flipped_sign_sqrt | flipped_sign_sqrt_i ELSE r)
	rr.Select(rPrime, rr, flippedSignSqrt|flippedSignSqrtI)

	r.Absolute(rr) // Choose the nonnegative square root.
	return r, correctSignSqrt | flippedSignSqrt
}
