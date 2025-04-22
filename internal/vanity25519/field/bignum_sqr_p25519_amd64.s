// Translated from the corresponding s2n-bignum function:
// https://github.com/awslabs/s2n-bignum/blob/main/x86/curve25519/bignum_sqr_p25519.S

//go:build amd64 && gc && !purego

#include "textflag.h"

#define z DI
#define x SI

// Use this fairly consistently for a zero
#define zero BX
#define zeroe BX

// Add rdx * m into a register-pair (high,low)
// maintaining consistent double-carrying with adcx and adox,
// using rax and rcx as temporaries
#define mulpadd(high, low, m) \
	MULXQ m, AX, CX; \
	ADCXQ AX, low;   \
	ADOXQ CX, high

// mulpade(high,low,m) adds rdx * m to a register-pair (high,low)
// maintaining consistent double-carrying with adcx and adox,
// using rax as a temporary, assuming high created from scratch
// and that zero has value zero.
#define mulpade(high, low, m) \
	MULXQ m, high, AX; \
	ADCXQ AX, low;     \
	ADOXQ zero, high

// func bignum_sqr_p25519(out *Element, a *Element)
TEXT ·bignum_sqr_p25519(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), z
	MOVQ a+8(FP), x

	// Save more registers to play with
	PUSHQ BX
	PUSHQ R12
	PUSHQ R13
	PUSHQ R14
	PUSHQ R15

	// Compute [r15;r8] = [00] which we use later, but mainly
	// set up an initial window [r14;...;r9] = [23;03;01]
	MOVQ  (x), DX
	MULXQ DX, R8, R15
	MULXQ 8(x), R9, R10
	MULXQ 24(x), R11, R12
	MOVQ  16(x), DX
	MULXQ 24(x), R13, R14

	// Clear our zero register, and also initialize the flags for the carry chain
	XORL zeroe, zeroe

	// Chain in the addition of 02 + 12 + 13 to that window (no carry-out possible)
	// This gives all the "heterogeneous" terms of the squaring ready to double
	mulpadd(R11,R10,(x))
	mulpadd(R12,R11,8(x))
	MOVQ  24(x), DX
	mulpadd(R13,R12,8(x))
	ADCXQ zero, R13
	ADOXQ zero, R14
	ADCQ  zero, R14

	// Double and add to the 00 + 11 + 22 + 33 terms, while also
	// pre-estimating the quotient from early results.
	XORL  zeroe, zeroe
	ADCXQ R9, R9
	ADOXQ R15, R9
	MOVQ  8(x), DX
	MULXQ DX, AX, CX
	ADCXQ R10, R10
	ADOXQ AX, R10
	ADCXQ R11, R11
	ADOXQ CX, R11
	MOVQ  16(x), DX
	MULXQ DX, AX, CX
	ADCXQ R12, R12
	ADOXQ AX, R12
	ADCXQ R13, R13
	ADOXQ CX, R13
	MOVQ  24(x), DX
	MULXQ DX, AX, R15

	MOVL  $38, DX
	MULXQ R15, DX, CX

	ADCXQ R14, R14
	ADOXQ AX, R14
	ADCXQ zero, R15
	ADOXQ zero, R15

	ADDQ  R11, DX
	ADCQ  zero, CX
	SHLQ  $1, DX, CX
	LEAQ  1(CX), BX
	IMULQ $19, BX

	// Now we have the full 8-digit product 2^256 * h + l where
	// h = [r15,r14,r13,r12] and l = [r11,r10,r9,r8]
	// and this is == 38 * h + l (mod p_25519)
	// We add in the precalculated 19 * q as well.
	// This is kept in 4 words since we have enough information there.
	XORL  AX, AX
	ADOXQ BX, R8
	MOVL  $38, DX
	mulpadd(R9,R8,R12)
	mulpadd(R10,R9,R13)
	mulpadd(R11,R10,R14)
	MULXQ R15, AX, CX
	ADCQ  AX, R11

	// We still haven't made the -2^255 * q contribution yet. Since we
	// are now safely in 4 words we just need a single bit of q, and we
	// can actually use the LSB of rcx = 19 * q since 19 is odd. And we
	// don't literally need to subtract, just to see whether we would
	// have a top 1 bit if we did, meaning we need to correct in the
	// last step by adding 2^255 - 19.
	XORL    CX, CX
	SHLQ    $63, BX
	CMPQ    R11, BX
	MOVL    $19, AX
	CMOVQPL CX, AX

	// Now make that possible correction and finally mask to 255 bits
	SUBQ AX, R8
	SBBQ CX, R9
	SBBQ CX, R10
	SBBQ CX, R11
	BTRQ $63, R11

	// Write everything back
	MOVQ R8, (z)
	MOVQ R9, 8(z)
	MOVQ R10, 16(z)
	MOVQ R11, 24(z)

	// Restore registers and return
	POPQ R15
	POPQ R14
	POPQ R13
	POPQ R12
	POPQ BX

	RET
