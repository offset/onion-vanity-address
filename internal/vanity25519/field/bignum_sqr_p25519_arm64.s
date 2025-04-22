// Translated from the corresponding s2n-bignum function:
// https://github.com/awslabs/s2n-bignum/blob/main/arm/curve25519/bignum_sqr_p25519.S

//go:build arm64 && gc && !purego

#include "textflag.h"

#define z R0
#define x R1

// Variables
#define u0 R2
#define u1 R3
#define u2 R4
#define u3 R5
#define u4 R6
#define u5 R7
#define u6 R8
#define u7 R9

#define u0short R2
#define u1short R3
#define u2short R4
#define u3short R5
#define u4short R6
#define u5short R7
#define u6short R8
#define u7short R9

#define c R10
#define cshort R10
#define l R11
#define lshort R11
#define h R12
#define hshort R12
#define q R13
#define qshort R13

#define t1 R14
#define t1short R14
#define t2 R15
#define t2short R15
#define t3 R16
#define t3short R16

// func bignum_sqr_p25519(out *Element, a *Element)
TEXT ·bignum_sqr_p25519(SB), NOSPLIT, $0-16
	MOVD out+0(FP), z
	MOVD a+8(FP), x

	// First just a near-clone of bignum_sqr_4_8 to get the square, using
	// different registers to collect full product without writeback.
	LDP   (x), (c, l)
	LDP   16(x), (h, q)
	UMULL cshort, cshort, u0
	LSR   $32, c, t1
	UMULL t1short, t1short, u1
	UMULL t1short, cshort, t1
	ADDS  t1<<33, u0, u0
	LSR   $31, t1, t1
	ADC   t1, u1, u1
	UMULL lshort, lshort, u2
	LSR   $32, l, t1
	UMULL t1short, t1short, u3
	UMULL t1short, lshort, t1
	MUL   l, c, t2
	UMULH l, c, t3
	ADDS  t1<<33, u2, u2
	LSR   $31, t1, t1
	ADC   t1, u3, u3
	ADDS  t2, t2, t2
	ADCS  t3, t3, t3
	ADC   ZR, u3, u3
	ADDS  t2, u1, u1
	ADCS  t3, u2, u2
	ADC   ZR, u3, u3
	UMULL hshort, hshort, u4
	LSR   $32, h, t1
	UMULL t1short, t1short, u5
	UMULL t1short, hshort, t1
	ADDS  t1<<33, u4, u4
	LSR   $31, t1, t1
	ADC   t1, u5, u5
	UMULL qshort, qshort, u6
	LSR   $32, q, t1
	UMULL t1short, t1short, u7
	UMULL t1short, qshort, t1
	MUL   q, h, t2
	UMULH q, h, t3
	ADDS  t1<<33, u6, u6
	LSR   $31, t1, t1
	ADC   t1, u7, u7
	ADDS  t2, t2, t2
	ADCS  t3, t3, t3
	ADC   ZR, u7, u7
	ADDS  t2, u5, u5
	ADCS  t3, u6, u6
	ADC   ZR, u7, u7
	SUBS  h, c, c
	SBCS  q, l, l
	CSETM CC, t3
	EOR   t3, c, c
	SUBS  t3, c, c
	EOR   t3, l, l
	SBC   t3, l, l
	ADDS  u2, u4, u4
	ADCS  u3, u5, u5
	ADCS  ZR, u6, u6
	ADC   ZR, u7, u7
	UMULL cshort, cshort, h
	LSR   $32, c, u3
	UMULL u3short, u3short, q
	UMULL u3short, cshort, u3
	ADDS  u3<<33, h, h
	LSR   $31, u3, u3
	ADC   u3, q, q
	UMULL lshort, lshort, t2
	LSR   $32, l, u3
	UMULL u3short, u3short, t1
	UMULL u3short, lshort, u3
	MUL   l, c, u2
	UMULH l, c, t3
	ADDS  u3<<33, t2, t2
	LSR   $31, u3, u3
	ADC   u3, t1, t1
	ADDS  u2, u2, u2
	ADCS  t3, t3, t3
	ADC   ZR, t1, t1
	ADDS  u2, q, q
	ADCS  t3, t2, t2
	ADC   ZR, t1, t1
	ADDS  u4, u0, u2
	ADCS  u5, u1, u3
	ADCS  u6, u4, u4
	ADCS  u7, u5, u5
	CSETM CC, t3
	SUBS  h, u2, u2
	SBCS  q, u3, u3
	SBCS  t2, u4, u4
	SBCS  t1, u5, u5
	ADCS  t3, u6, u6
	ADC   t3, u7, u7

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
