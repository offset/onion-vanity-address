// Translated from the corresponding s2n-bignum function:
// https://github.com/awslabs/s2n-bignum/blob/main/arm/curve25519/bignum_mul_p25519.S

//go:build arm64 && gc && !purego

#include "textflag.h"

#define z R0
#define x R1
#define y R2

#define a0 R3
#define a0short R3
#define a1 R4
#define b0 R5
#define b0short R5
#define b1 R6

#define u0 R7
#define u1 R8
#define u2 R9
#define u3 R10
#define u4 R11
#define u5 R12
#define u6 R13
#define u7 R14

#define u0short R7
#define u1short R8
#define u2short R9
#define u3short R10
#define u4short R11
#define u5short R12
#define u6short R13
#define u7short R14

#define t R15

#define sgn R16
#define ysgn R17

// These are aliases to registers used elsewhere including input pointers.
// By the time they are used this does not conflict with other uses.

#define m0 y
#define m1 ysgn
#define m2 t
#define m3 x
#define u u2

// For the reduction stages, again aliasing other things but not the u's

#define c R3
#define cshort R3
#define h R4
#define l R5
#define lshort R5
#define d R6
#define q R17
#define qshort R17

// func bignum_mul_p25519(out *Element, a *Element, b *Element)
TEXT ·bignum_mul_p25519(SB), NOSPLIT, $0-24
	MOVD out+0(FP), z
	MOVD a+8(FP), x
	MOVD b+16(FP), y

	// Multiply the low halves using Karatsuba 2x2->4 to get [u3,u2,u1,u0]
	LDP (x), (a0, a1)
	LDP (y), (b0, b1)

	UMULL b0short, a0short, u0
	LSR   $32, a0, R17
	UMULL b0short, R17, R15
	LSR   $32, b0, R16
	UMULL R17, R16, u1
	UMULL R16, a0short, R16
	ADDS  R15<<32, u0, u0
	LSR   $32, R15, R15
	ADC   R15, u1, u1
	ADDS  R16<<32, u0, u0
	LSR   $32, R16, R16
	ADC   R16, u1, u1

	MUL   b1, a1, u2
	UMULH b1, a1, u3

	SUBS  a0, a1, a1
	CNEG  CC, a1, a1
	CSETM CC, sgn

	ADDS u1, u2, u2
	ADC  ZR, u3, u3

	SUBS b1, b0, a0
	CNEG CC, a0, a0
	CINV CC, sgn, sgn

	MUL   a0, a1, t
	UMULH a0, a1, a0

	ADDS u2, u0, u1
	ADCS u3, u2, u2
	ADC  ZR, u3, u3

	CMN  $1, sgn
	EOR  sgn, t, t
	ADCS u1, t, u1
	EOR  sgn, a0, a0
	ADCS u2, a0, u2
	ADC  sgn, u3, u3

	// Multiply the high halves using Karatsuba 2x2->4 to get [u7,u6,u5,u4]
	LDP 16(x), (a0, a1)
	LDP 16(y), (b0, b1)

	UMULL b0short, a0short, u4
	LSR   $32, a0, R17
	UMULL b0short, R17, R15
	LSR   $32, b0, R16
	UMULL R17, R16, u5
	UMULL R16, a0short, R16
	ADDS  R15<<32, u4, u4
	LSR   $32, R15, R15
	ADC   R15, u5, u5
	ADDS  R16<<32, u4, u4
	LSR   $32, R16, R16
	ADC   R16, u5, u5

	MUL   b1, a1, u6
	UMULH b1, a1, u7

	SUBS  a0, a1, a1
	CNEG  CC, a1, a1
	CSETM CC, sgn

	ADDS u5, u6, u6
	ADC  ZR, u7, u7

	SUBS b1, b0, a0
	CNEG CC, a0, a0
	CINV CC, sgn, sgn

	MUL   a0, a1, t
	UMULH a0, a1, a0

	ADDS u6, u4, u5
	ADCS u7, u6, u6
	ADC  ZR, u7, u7

	CMN  $1, sgn
	EOR  sgn, t, t
	ADCS u5, t, u5
	EOR  sgn, a0, a0
	ADCS u6, a0, u6
	ADC  sgn, u7, u7

	// Compute  sgn,[a1,a0] = x_hi - x_lo
	// and     ysgn,[b1,b0] = y_lo - y_hi
	// sign-magnitude differences
	LDP   16(x), (a0, a1)
	LDP   (x), (t, sgn)
	SUBS  t, a0, a0
	SBCS  sgn, a1, a1
	CSETM CC, sgn

	LDP   (y), (t, ysgn)
	SUBS  b0, t, b0
	SBCS  b1, ysgn, b1
	CSETM CC, ysgn

	EOR  sgn, a0, a0
	SUBS sgn, a0, a0
	EOR  sgn, a1, a1
	SBC  sgn, a1, a1

	EOR  ysgn, b0, b0
	SUBS ysgn, b0, b0
	EOR  ysgn, b1, b1
	SBC  ysgn, b1, b1

	// Save the correct sign for the sub-product
	EOR sgn, ysgn, sgn

	// Add H' = H + L_top, still in [u7,u6,u5,u4]
	ADDS u2, u4, u4
	ADCS u3, u5, u5
	ADCS ZR, u6, u6
	ADC  ZR, u7, u7

	// Now compute the mid-product as [m3,m2,m1,m0]
	MUL   b0, a0, m0
	UMULH b0, a0, m1
	MUL   b1, a1, m2
	UMULH b1, a1, m3

	SUBS  a0, a1, a1
	CNEG  CC, a1, a1
	CSETM CC, u

	ADDS m1, m2, m2
	ADC  ZR, m3, m3

	SUBS b1, b0, b1
	CNEG CC, b1, b1
	CINV CC, u, u

	MUL   b1, a1, b0
	UMULH b1, a1, b1

	ADDS m2, m0, m1
	ADCS m3, m2, m2
	ADC  ZR, m3, m3

	CMN  $1, u
	EOR  u, b0, b0
	ADCS m1, b0, m1
	EOR  u, b1, b1
	ADCS m2, b1, m2
	ADC  u, m3, m3

	// Accumulate the positive mid-terms as [u7,u6,u5,u4,u3,u2]
	ADDS u0, u4, u2
	ADCS u1, u5, u3
	ADCS u4, u6, u4
	ADCS u5, u7, u5
	ADCS ZR, u6, u6
	ADC  ZR, u7, u7

	// Add in the sign-adjusted complex term
	CMN  $1, sgn
	EOR  sgn, m0, m0
	ADCS u2, m0, u2
	EOR  sgn, m1, m1
	ADCS u3, m1, u3
	EOR  sgn, m2, m2
	ADCS u4, m2, u4
	EOR  sgn, m3, m3
	ADCS u5, m3, u5
	ADCS sgn, u6, u6
	ADC  sgn, u7, u7

	// Now we have the full 8-digit product 2^256 * h + l where
	// h = [u7,u6,u5,u4] and l = [u3,u2,u1,u0]
	// and this is == 38 * h + l (mod p_25519).
	// We do the 38 * h + l using 32-bit multiplies avoiding umulh,
	// and pre-estimate and feed in the next-level quotient
	// q = h + 1 where h = an early version of the high 255 bits.
	// We add 2^255 * h - 19 * (h + 1), so end up offset by 2^255.
	MOVD $38, c

	UMULL  cshort, u4short, h
	ADD    u0short.UXTW, h, h
	LSR    $32, u0, u0
	LSR    $32, u4, u4
	UMADDL cshort, u0, u4, u4short
	MOVD   h, u0

	UMULL  cshort, u5short, h
	ADD    u1short.UXTW, h, h
	LSR    $32, u1, u1
	LSR    $32, u5, u5
	UMADDL cshort, u1, u5, u5short
	MOVD   h, u1

	UMULL  cshort, u6short, h
	ADD    u2short.UXTW, h, h
	LSR    $32, u2, u2
	LSR    $32, u6, u6
	UMADDL cshort, u2, u6, u6short
	MOVD   h, u2

	UMULL  cshort, u7short, h
	ADD    u3short.UXTW, h, h
	LSR    $32, u3, u3
	LSR    $32, u7, u7
	UMADDL cshort, u3, u7, u7short
	MOVD   h, u3

	LSR $31, u7, q

	MOVD   $19, l
	UMADDL qshort, lshort, l, l
	ADD    l, u0, u0

	ADDS u4<<32, u0, u0
	EXTR $32, u4, u5, c
	ADCS c, u1, u1
	EXTR $32, u5, u6, c
	ADCS c, u2, u2
	EXTR $32, u6, u7, c
	LSL  $63, q, l
	EOR  l, u3, u3
	ADC  c, u3, u3

	// Now we correct by a final 2^255-19 if the top bit is clear
	// meaning that the "real" pre-reduced result is negative.
	MOVD $19, c
	TST  $0x8000000000000000, u3
	CSEL PL, c, ZR, c
	SUBS c, u0, u0
	SBCS ZR, u1, u1
	SBCS ZR, u2, u2
	SBC  ZR, u3, u3
	AND  $~0x8000000000000000, u3, u3

	// Write back result
	STP (u0, u1), (z)
	STP (u2, u3), 16(z)
	RET
