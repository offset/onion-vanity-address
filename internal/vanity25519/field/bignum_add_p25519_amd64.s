// Translated from the corresponding s2n-bignum function:
// https://github.com/awslabs/s2n-bignum/blob/main/x86/curve25519/bignum_add_p25519.S

//go:build amd64 && gc && !purego

#include "textflag.h"

#define z DI
#define x SI
#define y DX

#define d0 R8
#define d1 R9
#define d2 R10
#define d3 R11

#define c0 AX
#define c1 CX
#define c2 SI
#define c3 DX

// func bignum_add_p25519(out *Element, a *Element, b *Element)
TEXT ·bignum_add_p25519(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), z
	MOVQ a+8(FP), x
	MOVQ b+16(FP), y

	// Add as [d3; d2; d1; d0] = x + y; since we assume x, y < 2^255 - 19
	// this sum fits in 256 bits.
	MOVQ (x), d0
	ADDQ (y), d0
	MOVQ 8(x), d1
	ADCQ 8(y), d1
	MOVQ 16(x), d2
	ADCQ 16(y), d2
	MOVQ 24(x), d3
	ADCQ 24(y), d3

	// Now x + y >= 2^255 - 19 <=> x + y + 19 >= 2^255.
	// Form [c3; c2; c1; c0] = (x + y) + 19
	MOVL $19, c0
	XORL c1, c1
	XORL c2, c2
	XORL c3, c3

	ADDQ d0, c0
	ADCQ d1, c1
	ADCQ d2, c2
	ADCQ d3, c3

	// Test the top bit to see if this is >= 2^255, and clear it as a masking
	// so that in that case the result is exactly (x + y) - (2^255 - 19).
	// Then select the output according to that top bit as that or just x + y.
	BTRQ    $63, c3
	CMOVQCS c0, d0
	CMOVQCS c1, d1
	CMOVQCS c2, d2
	CMOVQCS c3, d3

	// Store the result
	MOVQ d0, (z)
	MOVQ d1, 8(z)
	MOVQ d2, 16(z)
	MOVQ d3, 24(z)
	RET
