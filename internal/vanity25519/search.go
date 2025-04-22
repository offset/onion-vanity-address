// Package vanity25519 implements an efficient [curve25519] vanity key generator.
//
// This package provides functions to generate vanity curve25519 key pair with a specific pattern in its public key.
// It uses an optimized search algorithm that generates candidate public keys by adding offsets to the start public key,
// avoiding the need to perform full scalar multiplication for each candidate.
//
// The algorithm has amortized cost (3.5M + 3A) per candidate key, where M is field multiplication and A is field addition.
//
// For comparison, brute-force key pair generator requires
// 2561 field multiplications using [square-and-multiply] or
// 743 field multiplications using [Twisted Edwards curve] per candidate key.
//
// [curve25519]: https://datatracker.ietf.org/doc/html/rfc7748#section-4.1
// [square-and-multiply]: https://github.com/golang/go/commit/e005cdc62081130117a3fa30d01cd28ee076ed93
// [Twisted Edwards curve]: https://github.com/FiloSottile/edwards25519/commit/2941d4c8cdacb392a1b39f85adafaeae65bb50f6
package vanity25519

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"slices"

	"github.com/offset/onion-vanity-address/internal/edwards25519"
	"github.com/offset/onion-vanity-address/internal/vanity25519/field"
)

// Search generates candidate curve25519 public keys by adding batches of incrementing offsets to the start public key.
// Once matching candidate is found the corresponding private key can be obtained from its offset using [Add] function.
//
// Parameters:
//   - startPublicKey: the start curve25519 public key to generate candidates from
//   - startOffset: the initial offset to start generating candidates from
//   - batchSize: number of candidates to generate per batch, must be positive and even
//   - accept: function that evaluates each candidate public key (hence it must be fast) and retruns true to accept the key
//   - yield: function called for each accepted candidate public key and its offset from the start key
//
// Performance: amortized (3.5M + 3A) per candidate key, where M is field multiplication and A is field addition.
//
// The search continues until context is done and returns number of generated candidates.
// The function panics if batchSize is not positive and even, or if startPublicKey is not a valid curve25519 public key.
func Search(ctx context.Context, startPublicKey []byte, startOffset *big.Int, batchSize int, accept func(candidatePublicKey []byte) bool, yield func(publicKey []byte, offset *big.Int)) uint64 {
	if startOffset == nil || startOffset.Sign() == -1 {
		panic("startOffset must be non-negative")
	}
	if batchSize <= 0 || batchSize%2 != 0 {
		panic("batchSize must be positive and even")
	}

	p, err := pointFromBytesWithOffset(startPublicKey, startOffset)
	if err != nil {
		panic(err)
	}

	offsets := makeOffsets(batchSize / 2)

	batchOffset := new(point).set(&offsets[0])
	batchOffset.add(batchOffset, &offsets[batchSize/2-1])
	batchOffset.add(batchOffset, &offsets[batchSize/2-1])

	x := make([]field.Element, batchSize)
	dx := make([]field.Element, batchSize/2+1)
	var bm [32]byte

	// shift by half of the batch size to avoid negative offset
	p.add(p, &offsets[batchSize/2-1])
	for i := uint64(batchSize / 2); ; i += uint64(batchSize + 1) {
		select {
		case <-ctx.Done():
			return i - uint64(batchSize/2)
		default:
		}
		// [addXBatch] inverts last element of dx
		dx[batchSize/2].Subtract(&batchOffset.x, &p.x)

		addXBatch(p, offsets, dx, x)

		for j := range x {
			if accept(x[j].FillBytes(bm[:])) {
				offset := new(big.Int).Add(startOffset, new(big.Int).SetUint64(i))
				if j < batchSize/2 {
					offset.Add(offset, big.NewInt(int64(j+1)))
				} else {
					offset.Sub(offset, big.NewInt(int64(j+1-batchSize/2)))
				}
				yield(slices.Clone(bm[:]), offset)
			}
		}

		if accept(p.x.FillBytes(bm[:])) {
			offset := new(big.Int).Add(startOffset, new(big.Int).SetUint64(i))
			yield(slices.Clone(bm[:]), offset)
		}

		// Complexity: 4M + 7A
		p.addDxInv(p, batchOffset, &dx[batchSize/2])
	}
}

// Add returns curve25519 private key obtained by adding offset found by [Search] function to the start private key.
func Add(startPrivateKey []byte, offset *big.Int) ([]byte, error) {
	startPublicKey, err := publicKeyFor(startPrivateKey)
	if err != nil {
		return nil, err
	}

	p, err := pointFromBytesWithOffset(startPublicKey, offset)
	if err != nil {
		return nil, err
	}
	vanityPublicKey := p.x.Bytes()

	s, err := new(field.Element).SetBytes(startPrivateKey)
	if err != nil {
		return nil, err
	}
	so := fieldElementFromBigInt(offset)
	so.Mult32(so, 8)

	// To find vanity private key check
	// both startPrivateKey + 8*offset and startPrivateKey - 8*offset
	// and return the one that produces the vanity public key.
	b := new(field.Element).Add(s, so).Bytes()
	k, err := publicKeyFor(b)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(k, vanityPublicKey) {
		return b, nil
	}

	b = new(field.Element).Subtract(s, so).Bytes()
	k, err = publicKeyFor(b)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(k, vanityPublicKey) {
		return b, nil
	}

	return nil, errors.New("offset does not match private key")
}

// makeOffsets generates a slice of n points, where p[i] = B*8*(i+1).
func makeOffsets(n int) []point {
	if n <= 0 {
		panic("n must be greater than 0")
	}
	offsets := make([]point, n)
	offsets[0].set(_B8)
	if n > 1 {
		offsets[1].set(new(point).double(_B8))
		for i := 2; i < n; i++ {
			offsets[i].set(new(point).add(&offsets[i-1], _B8))
		}
	}
	return offsets
}

// addXBatch adds a batch of n points to a given point p1 and
// returns x-coordinates of the 2*n resulting points:
//
//	x = {p1 + p2s[0], ... , p1 + p2s[n-1], p1 - p2s[0], ... , p1 - p2s[n-1]}
//
// Complexity for 2*n resulting x-coordinates:
//
//	(4M + 6A)*n + 3M*(n+1) + 262M + 1A = (7M + 6A)*n + 265M + 1A
//
// I.e. (3.5M + 3A) per resulting x-coordinate amortized.
//
// It requires:
//
//	len(dx) = n+1, uses dx[:n] as a scratch buffer and calculates dx[n] = 1/dx[n]
//	len(x)  = 2*n, for resulting x-coordinates
func addXBatch(p1 *point, p2s []point, dx, x []field.Element) {
	var Ax1, Ax1x2, t field.Element
	n := len(p2s)

	// p3  = p1 + p2
	// p3' = p1 - p2
	//
	// Montgomery curve point addition formula for x-coordinate:
	// x3 = ((y2 - y1) / (x2 - x1))^2 - A - x1 - x2 = ((y2 - y1)/dx)^2 - (A + x1 + x2)
	//
	// for p2' = -p2, x2' = x2, y2' = -y2:
	// x3' = ((-y2 - y1) / (x2 - x1))^2 - A - x1 - x2 = ((y2 + y1)/dx)^2 - (A + x1 + x2)

	for i := range n {
		dx[i].Subtract(&p2s[i].x, &p1.x)
	}
	invert(dx, x)

	Ax1.Add(_A, &p1.x)
	for i := range n {
		p2 := &p2s[i]
		Ax1x2.Add(&Ax1, &p2.x)

		t.Subtract(&p2.y, &p1.y)
		t.Multiply(&t, &dx[i])
		t.Square(&t)
		x[i].Subtract(&t, &Ax1x2)

		t.Add(&p2.y, &p1.y)
		t.Multiply(&t, &dx[i])
		t.Square(&t)
		x[n+i].Subtract(&t, &Ax1x2)
	}
}

// invert calculates a[i] = 1/a[i] using b as a scratch buffer.
//
// It uses:
//
//	3*(n-1) multiplications
//	1 invert = ~265 multiplications
//
// Complexity: 3M*n + 262M
//
// https://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Multiple_inverses
func invert(a, b []field.Element) {
	var t field.Element
	n := len(a)
	pa := new(field.Element).Set(&a[0]) // a[0]*a[1]*...*a[n]
	for i := 1; i < n; i++ {
		b[i].Set(pa)
		pa.Multiply(pa, &a[i])
	}

	paInv := new(field.Element).Invert(pa)

	for i := n - 1; i > 0; i-- {
		t.Multiply(paInv, &b[i])
		paInv.Multiply(paInv, &a[i])
		a[i].Set(&t)
	}
	a[0].Set(paInv)
}

// pointFromBytesWithOffset creates one of two points
// from a Montgomery u-coordinate bytes and adds B*8*offset to it.
func pointFromBytesWithOffset(b []byte, offset *big.Int) (*point, error) {
	p, err := edwardsPointFromMontgomeryBytes(b)
	if err != nil {
		return nil, err
	}

	po := new(edwards25519.Point).ScalarBaseMult(scalarFromBigInt(offset))
	po.MultByCofactor(po)
	p.Add(p, po)

	return montgomeryFromEdwards(p), nil
}

// edwardsPointFromMontgomeryBytes returns corresponding [edwards25519.Point] or error.
//
// https://datatracker.ietf.org/doc/html/rfc7748#section-4.1
func edwardsPointFromMontgomeryBytes(b []byte) (*edwards25519.Point, error) {
	u, err := new(field.Element).SetBytes(b)
	if err != nil {
		return nil, err
	}

	// y = (u - 1) / (u + 1)
	var y, t field.Element

	t.Add(u, _1)
	t.Invert(&t)
	y.Subtract(u, _1)
	y.Multiply(&y, &t)

	return new(edwards25519.Point).SetBytes(y.Bytes())
}

func publicKeyFor(privateKey []byte) ([]byte, error) {
	s, err := new(edwards25519.Scalar).SetBytesWithClamping(privateKey)
	if err != nil {
		return nil, err
	}
	return new(edwards25519.Point).ScalarBaseMult(s).BytesMontgomery(), nil
}
