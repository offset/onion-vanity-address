package main

import (
	"context"
	"math/big"
	"slices"

	"github.com/offset/onion-vanity-address/internal/edwards25519"
	"github.com/offset/onion-vanity-address/internal/vanity25519/field"
)

// _B8 = 8*_B - base point times cofactor
var _B8 = new(edwards25519.Point).MultByCofactor(edwards25519.NewGeneratorPoint())

// search generates candidate edwards25519 public keys by adding batches of incrementing offsets to the start public key.
// Once matching candidate is found the corresponding private key can be obtained from its offset using [add] function.
//
// Parameters:
//   - startPublicKey: the start edwards25519 public key to generate candidates from
//   - startOffset: the initial offset to start generating candidates from
//   - batchSize: number of candidates to generate per batch, must be positive and even
//   - accept: function that evaluates each candidate public key (hence it must be fast) and returns true to accept the key
//   - yield: function called for each accepted candidate public key and its offset from the start key
//
// Performance: amortized (5M + 2A) per candidate key, where M is field multiplication and A is field addition.
//
// The candidate public key most significant bit is always zero.
// The search continues until context is done and returns number of generated candidates.
// The function panics if batchSize is not positive and even, or if startPublicKey is not a valid edwards25519 public key.
func search(ctx context.Context, startPublicKey []byte, startOffset *big.Int, batchSize int, accept func(candidatePublicKey []byte) bool, yield func(publicKey []byte, offset *big.Int)) uint64 {
	if startOffset == nil || startOffset.Sign() == -1 {
		panic("startOffset must be non-negative")
	}
	if batchSize <= 0 || batchSize%2 != 0 {
		panic("batchSize must be positive and even")
	}

	p, err := new(edwards25519.Point).SetBytes(startPublicKey)
	if err != nil {
		panic(err)
	}

	po := new(edwards25519.Point).ScalarMult(scalarFromBigInt(startOffset), _B8)
	p.Add(p, po)

	ynum := make([]field.Element, batchSize+1)
	yden := make([]field.Element, batchSize+1)
	y := make([]field.Element, batchSize+1) // y = ynum / yden

	// offsets[i] = (i+1) * _B8
	offsets := make([]affine, batchSize/2)
	poi := new(edwards25519.Point).Set(_B8)
	for i := range batchSize/2 - 1 {
		offsets[i].fromP3(poi)
		poi.Add(poi, _B8)
	}
	offsets[batchSize/2-1].fromP3(poi)

	// batchOffset = (batchSize+1) * _B8
	batchOffset := new(edwards25519.Point).Set(_B8)
	batchOffset.Add(batchOffset, poi)
	batchOffset.Add(batchOffset, poi)

	// Shift by half of the batch size to avoid negative offset
	p.Add(p, poi)

	// Center point for the current batch
	pa := new(affine).fromP3(p)

	var x1y2, y1x2 field.Element
	var yb [32]byte

	// One iteration tests batchSize y-coordinates of the
	// batch = {p + _B8, ... , p + batchSize/2*_B8, p − _B8, ... , p − batchSize/2*_B8}
	// as well as the center point p.
	//
	// Complexity: (5M + 2A)*batchSize + 278M + 9A
	for i := uint64(batchSize / 2); ; i += uint64(batchSize + 1) {
		select {
		case <-ctx.Done():
			return i - uint64(batchSize/2)
		default:
		}

		// Affine addition formulae (independent of d) for twisted Edwards curves,
		// see https://eprint.iacr.org/2008/522.pdf
		//
		// y3 = (x1*y1 − x2*y2) / (x1*y2 − y1*x2) = num / den
		//
		// Symmetric negative point p2' = −p2 has y2' = y2 and x2' = −x2, therefore
		//
		// y3' = (x1*y1 + x2*y2) / (x1*y2 + y1*x2)
		//
		// Complexity: (2M + 4A)*batchSize/2 = (1M + 2A)*batchSize
		for j := range batchSize / 2 {
			p1, p2 := pa, &offsets[j]

			x1y2.Multiply(&p1.X, &p2.Y)
			y1x2.Multiply(&p1.Y, &p2.X)

			// p3 = p1 + p2
			// y3 = (x1*y1 − x2*y2) / (x1*y2 − y1*x2) = num / den
			ynum[j].Subtract(&p1.XY, &p2.XY)
			yden[j].Subtract(&x1y2, &y1x2)

			// p3' = p1 − p2
			// y3' = (x1*y1 + x2*y2) / (x1*y2 + y1*x2) = num / den
			ynum[batchSize/2+j].Add(&p1.XY, &p2.XY)
			yden[batchSize/2+j].Add(&x1y2, &y1x2)
		}

		// Complexity: 9M + 9A
		p.Add(p, batchOffset)

		// Piggyback on vector division to calculate 1/p.Z
		_, _, pZ, _ := p.ExtendedCoordinates()
		ynum[batchSize].One()
		yden[batchSize].SetBytes(pZ.Bytes())
		pZinv := &y[batchSize]

		// Complexity: 262M + 4M*(batchSize+1) = 4M*batchSize + 266M
		vectorDivision(ynum, yden, y)

		// Check each candidate in the batch
		for j := range batchSize {
			copy(yb[:], y[j].Bytes()) // eliminate field.Element.Bytes() allocations
			if accept(yb[:]) {
				offset := new(big.Int).Add(startOffset, new(big.Int).SetUint64(i))
				if j < batchSize/2 {
					offset.Add(offset, big.NewInt(int64(j+1)))
				} else {
					offset.Sub(offset, big.NewInt(int64(j+1-batchSize/2)))
				}
				yield(slices.Clone(yb[:]), offset)
			}
		}

		// Check center point of the batch
		copy(yb[:], pa.Y.Bytes()) // eliminate field.Element.Bytes() allocations
		if accept(yb[:]) {
			offset := new(big.Int).Add(startOffset, new(big.Int).SetUint64(i))
			yield(slices.Clone(yb[:]), offset)
		}

		// Complexity: 3M
		pa.fromP3zInv(p, pZinv)
	}
}

// add returns edwards25519 private key obtained by adding offset found by [search] function to the start private key.
func add(startPrivateKey []byte, offset *big.Int) ([]byte, error) {
	s, err := new(field.Element).SetBytes(startPrivateKey)
	if err != nil {
		return nil, err
	}
	so := fieldElementFromBigInt(offset)
	so.Mult32(so, 8)

	b := new(field.Element).Add(s, so).Bytes()
	return b, nil
}

// publicKeyFor returns edwards25519 public key for the given private key.
func publicKeyFor(privateKey []byte) ([]byte, error) {
	s, err := new(edwards25519.Scalar).SetBytesWithClamping(privateKey)
	if err != nil {
		return nil, err
	}
	return new(edwards25519.Point).ScalarBaseMult(s).Bytes(), nil
}

// vectorDivision calculates u = x / y
//
// It uses:
//
//	4*(n-1)+1 multiplications
//	1 invert = ~265 multiplications
//
// Complexity: 262M + 4M*n
//
// Simultaneous field divisions: an extension of Montgomery's trick
// David G. Harris
// https://eprint.iacr.org/2008/199.pdf
func vectorDivision(x, y, u []field.Element) {
	n := len(x)
	py := new(field.Element).Set(&y[0]) // y[0]*y[1]*...*y[n]
	for i := 1; i < n; i++ {
		u[i].Multiply(py, &x[i])
		py.Multiply(py, &y[i])
	}

	pyInv := new(field.Element).Invert(py)

	for i := n - 1; i > 0; i-- {
		u[i].Multiply(pyInv, &u[i])
		pyInv.Multiply(pyInv, &y[i])
	}
	u[0].Multiply(pyInv, &x[0])
}

type affine struct {
	X, Y, XY field.Element
}

// Complexity: 1I + 3M = 268M
func (v *affine) fromP3(p *edwards25519.Point) *affine {
	ex, ey, ez, _ := p.ExtendedCoordinates()
	X, _ := new(field.Element).SetBytes(ex.Bytes())
	Y, _ := new(field.Element).SetBytes(ey.Bytes())
	Z, _ := new(field.Element).SetBytes(ez.Bytes())

	var zInv field.Element
	zInv.Invert(Z)
	v.X.Multiply(X, &zInv)
	v.Y.Multiply(Y, &zInv)
	v.XY.Multiply(&v.X, &v.Y)
	return v
}

// Complexity: 3M
func (v *affine) fromP3zInv(p *edwards25519.Point, zInv *field.Element) *affine {
	ex, ey, _, _ := p.ExtendedCoordinates()
	X, _ := new(field.Element).SetBytes(ex.Bytes())
	Y, _ := new(field.Element).SetBytes(ey.Bytes())

	v.X.Multiply(X, zInv)
	v.Y.Multiply(Y, zInv)
	v.XY.Multiply(&v.X, &v.Y)
	return v
}

func scalarFromBigInt(n *big.Int) *edwards25519.Scalar {
	var buf [64]byte
	copy(buf[:], bigIntBytes(n))

	xs, err := edwards25519.NewScalar().SetUniformBytes(buf[:])
	if err != nil {
		panic(err)
	}
	return xs
}

func fieldElementFromBigInt(n *big.Int) *field.Element {
	return fieldElementFromBytes(bigIntBytes(n))
}

func fieldElementFromBytes(x []byte) *field.Element {
	var buf [32]byte
	copy(buf[:], x)
	fe, err := new(field.Element).SetBytes(buf[:])
	if err != nil {
		panic(err)
	}
	return fe
}

func bigIntBytes(n *big.Int) []byte {
	if n == nil || n.Sign() < 0 {
		panic("n must be non-negative")
	}
	if n.BitLen() > 255 {
		panic("n must be less than 2^255")
	}
	var buf [32]byte
	b := n.FillBytes(buf[:])
	slices.Reverse(b)
	return b
}
