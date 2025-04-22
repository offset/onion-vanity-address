// Translated from the corresponding s2n-bignum function:
// https://github.com/awslabs/s2n-bignum/blob/main/arm/curve25519/bignum_sub_p25519.S

//go:build arm64 && gc && !purego

#include "textflag.h"

#define z R0
#define x R1
#define y R2
#define c R3
#define l R4
#define d0 R5
#define d1 R6
#define d2 R7
#define d3 R8

// func bignum_sub_p25519(out *Element, a *Element, b *Element)
TEXT ·bignum_sub_p25519(SB), NOSPLIT, $0-24
	MOVD out+0(FP), z
	MOVD a+8(FP), x
	MOVD b+16(FP), y

	// First just subtract the numbers as [d3; d2; d1; d0] = x - y,
	// with the inverted carry flag meaning CF <=> x >= y.

	LDP  (x), (d0, d1)
	LDP  (y), (l, c)
	SUBS l, d0, d0
	SBCS c, d1, d1
	LDP  16(x), (d2, d3)
	LDP  16(y), (l, c)
	SBCS l, d2, d2
	SBCS c, d3, d3

	// Now if x < y we want to add back p_25519, which staying within 255 bits
	// means subtracting 19, since p_25519 = 2^255 - 19.
	// Let c be that constant 19 when x < y, zero otherwise.

	MOVD $19, l
	CSEL LO, l, ZR, c

	// Correct by adding the optional constant and masking to 255 bits

	SUBS c, d0, d0
	SBCS ZR, d1, d1
	SBCS ZR, d2, d2
	SBC  ZR, d3, d3
	AND  $0x7FFFFFFFFFFFFFFF, d3, d3

	// Store the result
	STP (d0, d1), (z)
	STP (d2, d3), 16(z)

	RET
