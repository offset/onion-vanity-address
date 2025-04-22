//go:build arm64 && gc && !purego

package field

// bignum_add_p25519 sets out = a + b.
//
//go:noescape
func bignum_add_p25519(out *Element, a *Element, b *Element)

// bignum_sub_p25519 sets out = a - b.
//
//go:noescape
func bignum_sub_p25519(out *Element, a *Element, b *Element)

// bignum_mul_p25519 sets out = a * b.
//
//go:noescape
func bignum_mul_p25519(out *Element, a *Element, b *Element)

// bignum_sqr_p25519 sets out = a * a.
//
//go:noescape
func bignum_sqr_p25519(out *Element, a *Element)
