// Translated from the corresponding s2n-bignum function:
// https://github.com/awslabs/s2n-bignum/blob/main/x86/curve25519/bignum_sub_p25519.S

//go:build amd64 && gc && !purego

#include "textflag.h"

#define z DI
#define x SI
#define y DX

#define d0 R8
#define d1 R9
#define d2 R10
#define d3 R11

#define zero AX
#define c CX

// func bignum_sub_p25519(out *Element, a *Element, b *Element)
TEXT ·bignum_sub_p25519(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), z
	MOVQ a+8(FP), x
	MOVQ b+16(FP), y

	// Load and subtract the two inputs as [d3;d2;d1;d0] = x - y (modulo 2^256)
	MOVQ (x), d0
	SUBQ (y), d0
	MOVQ 8(x), d1
	SBBQ 8(y), d1
	MOVQ 16(x), d2
	SBBQ 16(y), d2
	MOVQ 24(x), d3
	SBBQ 24(y), d3

	// Now if x < y we want to add back p_25519, which staying within 4 digits
	// means subtracting 19, since p_25519 = 2^255 - 19.
	// Let c be that constant 19 when x < y, zero otherwise.
	SBBQ c, c
	XORL zero, zero
	ANDQ $19, c

	// Correct by adding the optional constant and masking to 255 bits
	SUBQ c, d0
	MOVQ d0, (z)
	SBBQ zero, d1
	MOVQ d1, 8(z)
	SBBQ zero, d2
	MOVQ d2, 16(z)
	SBBQ zero, d3
	BTRQ $63, d3
	MOVQ d3, 24(z)
	RET
