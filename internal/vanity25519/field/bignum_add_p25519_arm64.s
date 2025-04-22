// Translated from the corresponding s2n-bignum function:
// https://github.com/awslabs/s2n-bignum/blob/main/arm/curve25519/bignum_add_p25519.S

//go:build arm64 && gc && !purego

#include "textflag.h"

#define z R0
#define x R1
#define y R2
#define d0 R3
#define d1 R4
#define d2 R5
#define d3 R6
#define c0 R7
#define c1 R8
#define c2 R9
#define c3 R10

// func bignum_add_p25519(out *Element, a *Element, b *Element)
TEXT ·bignum_add_p25519(SB), NOSPLIT, $0-24
	MOVD out+0(FP), z
	MOVD a+8(FP), x
	MOVD b+16(FP), y

	// Add as [d3; d2; d1; d0] = x + y; since we assume x, y < 2^255 - 19
	// this sum fits in 256 bits
	LDP  (x), (d0, d1)
	LDP  (y), (c0, c1)
	ADDS c0, d0, d0
	ADCS c1, d1, d1
	LDP  16(x), (d2, d3)
	LDP  16(y), (c0, c1)
	ADCS c0, d2, d2
	ADC  c1, d3, d3

	// Now x + y >= 2^255 - 19 <=> x + y + (2^255 + 19) >= 2^256
	// Form [c3; c2; c1; c0] = (x + y) + (2^255 + 19), with CF for the comparison
	MOVD $0x8000000000000000, c3
	ADDS $19, d0, c0
	ADCS ZR, d1, c1
	ADCS ZR, d2, c2
	ADCS c3, d3, c3

	// If the comparison holds, select [c3; c2; c1; c0]. There's no need to mask
	// it since in this case it is ((x + y) + (2^255 + 19)) - 2^256 because the
	// top carry is lost, which is the desired (x + y) - (2^255 - 19).
	CSEL CC, d0, c0, d0
	CSEL CC, d1, c1, d1
	CSEL CC, d2, c2, d2
	CSEL CC, d3, c3, d3

	// Store the result
	STP (d0, d1), (z)
	STP (d2, d3), 16(z)
	RET
