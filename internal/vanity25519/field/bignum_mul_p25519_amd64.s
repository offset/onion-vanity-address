// Translated from the corresponding s2n-bignum function:
// https://github.com/awslabs/s2n-bignum/blob/main/x86/curve25519/bignum_mul_p25519.S

//go:build amd64 && gc && !purego

#include "textflag.h"

#define z DI
#define x SI
#define y CX

// A zero register
#define zero BP
#define zeroe BP

// mulpadd(high,low,m) adds rdx * m to a register-pair (high,low)
// maintaining consistent double-carrying with adcx and adox,
// using rax and rbx as temporaries.
#define mulpadd(high, low, m) \
	MULXQ m, AX, BX; \
	ADCXQ AX, low;   \
	ADOXQ BX, high

// mulpade(high,low,m) adds rdx * m to a register-pair (high,low)
// maintaining consistent double-carrying with adcx and adox,
// using rax as a temporary, assuming high created from scratch
// and that zero has value zero.
#define mulpade(high, low, m) \
	MULXQ m, AX, high; \
	ADCXQ AX, low;     \
	ADOXQ zero, high

// func bignum_mul_p25519(out *Element, a *Element, b *Element)
TEXT ·bignum_mul_p25519(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), z
	MOVQ a+8(FP), x
	MOVQ b+16(FP), y

	// Save more registers to play with
	PUSHQ BX
	PUSHQ BP
	PUSHQ R12
	PUSHQ R13
	PUSHQ R14
	PUSHQ R15

	// Zero a register, which also makes sure we don't get a fake carry-in
	XORL zeroe, zeroe

	// Do the zeroth row, which is a bit different
	MOVQ (y), DX

	MULXQ (x), R8, R9
	MULXQ 8(x), AX, R10
	ADDQ  AX, R9
	MULXQ 16(x), AX, R11
	ADCQ  AX, R10
	MULXQ 24(x), AX, R12
	ADCQ  AX, R11
	ADCQ  zero, R12

	// Add row 1
	XORL zeroe, zeroe
	MOVQ 8(y), DX

	mulpadd(R10,R9,(x))
	mulpadd(R11,R10,8(x))
	mulpadd(R12,R11,16(x))
	mulpade(R13,R12,24(x))
	ADCQ zero, R13

	// Add row 2
	XORL zeroe, zeroe
	MOVQ 16(y), DX

	mulpadd(R11,R10,(x))
	mulpadd(R12,R11,8(x))
	mulpadd(R13,R12,16(x))
	mulpade(R14,R13,24(x))
	ADCQ zero, R14

	// Add row 3; also use an early 38*r15+r11 to get a quotient estimate q
	// and then squeeze in a 19 * q computation to inject into the next
	// double-carry chain. At the end rcx = q and rax = 19 * q.
	XORL zeroe, zeroe
	MOVQ 24(y), DX

	mulpadd(R12,R11,(x))

	MULXQ 24(x), CX, R15

	mulpadd(R13,R12,8(x))
	mulpadd(R14,R13,16(x))

	MOVL  $38, DX
	MULXQ R15, AX, BX

	ADCXQ CX, R14
	ADOXQ zero, R15
	ADCQ  zero, R15

	ADDQ  R11, AX
	ADCQ  zero, BX
	BTQ   $63, AX
	ADCQ  BX, BX
	LEAQ  1(BX), CX
	IMULQ $19, CX

	// Now we have the full 8-digit product 2^256 * h + l where
	// h = [r15,r14,r13,r12] and l = [r11,r10,r9,r8]
	// and this is == 38 * h + l (mod p_25519)
	// We add in the precalculated 19 * q as well.
	// This is kept in 4 words since we have enough information there.
	XORL  zeroe, zeroe
	ADOXQ CX, R8

	mulpadd(R9,R8,R12)
	mulpadd(R10,R9,R13)
	mulpadd(R11,R10,R14)
	MULXQ R15, AX, BX
	ADCQ  AX, R11

	// We still haven't made the -2^255 * q contribution yet. Since we
	// are now safely in 4 words we just need a single bit of q, and we
	// can actually use the LSB of rcx = 19 * q since 19 is odd. And we
	// don't literally need to subtract, just to see whether we would
	// have a top 1 bit if we did, meaning we need to correct in the
	// last step by adding 2^255 - 19.
	SHLQ    $63, CX
	CMPQ    R11, CX
	MOVL    $19, AX
	CMOVQPL zero, AX

	// Now make that possible correction and finally mask to 255 bits
	SUBQ AX, R8
	SBBQ zero, R9
	SBBQ zero, R10
	SBBQ zero, R11
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
	POPQ BP
	POPQ BX
	RET
