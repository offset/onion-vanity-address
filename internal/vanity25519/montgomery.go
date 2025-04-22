package vanity25519

import (
	"errors"

	"github.com/offset/onion-vanity-address/internal/edwards25519"
	edfield "github.com/offset/onion-vanity-address/internal/edwards25519/field"
	"github.com/offset/onion-vanity-address/internal/vanity25519/field"
)

// Montgomery "curve25519" v^2 = u^3 + A*u^2 + u parameters
//
// https://www.rfc-editor.org/rfc/rfc7748.html#section-4.1
var (
	// Constant A = 486662
	_A = fieldElementFromUint64(486662)
	// The base point is u = 9, v = 14781619447589544791020593568409986887264606134616475288964881837755586237401.
	_B = &point{
		x: *fieldElementFromUint64(9),
		y: *fieldElementFromString("14781619447589544791020593568409986887264606134616475288964881837755586237401"),
	}
	// _B8 = 8*_B - base point times cofactor
	_B8 = new(point).double(new(point).double(new(point).double(_B)))
)

// Constant 1
var _1 = new(field.Element).One()

// Constant -|sqrt(-486664)| - the scaling factor for bi-rational map
// calculated such that Edwards generator point maps to Montgomery base point.
var sqrt486664 = func() *field.Element {
	var t field.Element
	t.Negate(fieldElementFromUint64(486664))
	t.SqrtRatio(&t, _1)
	return t.Negate(&t)
}()

type point struct {
	x, y field.Element
}

func (m *point) set(p *point) *point {
	m.x.Set(&p.x)
	m.y.Set(&p.y)
	return m
}

// setBytes sets point coordinates from the little-endian x-coordinate bytes slice.
func (m *point) setBytes(xb []byte) (*point, error) {
	x, err := new(field.Element).SetBytes(xb)
	if err != nil {
		return nil, err
	}

	// y^2 = x^3 + A*x^2 + x
	var xSquared, ySquared, t field.Element

	xSquared.Square(x)
	ySquared.Multiply(&xSquared, x)
	t.Multiply(_A, &xSquared)
	ySquared.Add(&ySquared, &t)
	ySquared.Add(&ySquared, x)

	y, wasSquare := t.SqrtRatio(&ySquared, _1)
	if wasSquare == 0 {
		return nil, errors.New("not a valid point")
	}

	m.x.Set(x)
	m.y.Set(y)
	return m, nil
}

// https://en.wikipedia.org/wiki/Montgomery_curve
//
// Montgomery curve point addition formula for x-coordinate:
// x3 = ((y2 - y1) / (x2 - x1))^2 - A - x1 - x2
func addX(x3 *field.Element, p1, p2 *point) {
	var dy, dx, slope, slopeSquared, x2A field.Element

	x2A.Add(&p2.x, _A) // this can be cached

	dy.Subtract(&p2.y, &p1.y)
	dx.Subtract(&p2.x, &p1.x)

	dx.Invert(&dx)
	slope.Multiply(&dy, &dx)
	slopeSquared.Square(&slope)

	x3.Subtract(&slopeSquared, &p1.x)
	x3.Subtract(x3, &x2A)
}

// https://en.wikipedia.org/wiki/Montgomery_curve
//
// Montgomery curve point addition formula for y-coordinate:
// y3 = (2*x1 + x2 + A) * ((y2 - y1) / (x2 - x1)) - ((y2 - y1) / (x2 - x1))^3 - y1
func addY(y3 *field.Element, p1, p2 *point) {
	var xSum, dy, dx, slope, slopeCubed, x2A field.Element

	x2A.Add(&p2.x, _A) // this can be cached

	xSum.Add(&p1.x, &p1.x)
	xSum.Add(&xSum, &x2A)

	dy.Subtract(&p2.y, &p1.y)
	dx.Subtract(&p2.x, &p1.x)

	dx.Invert(&dx)
	slope.Multiply(&dy, &dx)

	slopeCubed.Square(&slope)
	slopeCubed.Multiply(&slopeCubed, &slope)

	y3.Multiply(&xSum, &slope)
	y3.Subtract(y3, &slopeCubed)
	y3.Subtract(y3, &p1.y)
}

// https://en.wikipedia.org/wiki/Montgomery_curve
//
// Montgomery curve point addition formulae:
// x3 = ((y2 - y1) / (x2 - x1))^2 - A - x1 - x2
// y3 = (2*x1 + x2 + A) * ((y2 - y1) / (x2 - x1)) - ((y2 - y1) / (x2 - x1))^3 - y1
func (m *point) add(p1, p2 *point) *point {
	var dxInv field.Element
	dxInv.Subtract(&p2.x, &p1.x)
	dxInv.Invert(&dxInv)

	return m.addDxInv(p1, p2, &dxInv)
}

// See [point.add], dxInv = 1/(x2 - x1)
// Complexity: 4M + 7A
func (m *point) addDxInv(p1, p2 *point, dxInv *field.Element) *point {
	var x3, y3 field.Element
	var dy, slope, slopeSquared, slopeCubed, x2A field.Element
	var x12A, xSum field.Element

	x2A.Add(&p2.x, _A) // this can be cached

	dy.Subtract(&p2.y, &p1.y)

	slope.Multiply(&dy, dxInv)
	slopeSquared.Square(&slope)
	slopeCubed.Multiply(&slopeSquared, &slope)

	x12A.Add(&p1.x, &x2A)

	x3.Subtract(&slopeSquared, &x12A)

	xSum.Add(&p1.x, &x12A)

	y3.Multiply(&xSum, &slope)
	y3.Subtract(&y3, &slopeCubed)
	y3.Subtract(&y3, &p1.y)

	m.x.Set(&x3)
	m.y.Set(&y3)
	return m
}

// https://en.wikipedia.org/wiki/Montgomery_curve
//
// Montgomery curve point doubling formula:
// x3 = ((3*x1^2 + 2*A*x1 + 1) / (2*y1))^2 - A - 2*x1
// y3 = (3*x1 + A) * ((3*x1^2 + 2*A*x1 + 1) / (2*y1)) - ((3*x1^2 + 2*A*x1 + 1) / (2*y1))^3 - y1
func (m *point) double(p *point) *point {
	var _2x, _3x, A2x, xSum field.Element
	var t, tSquared, tCubed field.Element
	var x3, y3 field.Element

	_2x.Add(&p.x, &p.x)
	_3x.Add(&_2x, &p.x)

	A2x.Multiply(_A, &_2x)

	xSum.Multiply(&_3x, &p.x)
	xSum.Add(&xSum, &A2x)
	xSum.Add(&xSum, _1)

	t.Add(&p.y, &p.y)
	t.Invert(&t)
	t.Multiply(&xSum, &t)

	tSquared.Square(&t)
	tCubed.Multiply(&tSquared, &t)

	x3.Subtract(&tSquared, _A)
	x3.Subtract(&x3, &_2x)

	y3.Add(&_3x, _A)
	y3.Multiply(&y3, &t)
	y3.Subtract(&y3, &tCubed)
	y3.Subtract(&y3, &p.y)

	m.x.Set(&x3)
	m.y.Set(&y3)
	return m
}

// https://www.rfc-editor.org/rfc/rfc7748.html#section-4.1
// (u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)
func montgomeryFromEdwards(p *edwards25519.Point) *point {
	var x, y, u, v, t field.Element

	ex, ey, ez, _ := p.ExtendedCoordinates()
	X, _ := new(field.Element).SetBytes(ex.Bytes())
	Y, _ := new(field.Element).SetBytes(ey.Bytes())
	Z, _ := new(field.Element).SetBytes(ez.Bytes())

	t.Invert(Z)
	x.Multiply(X, &t) // x = X/Z
	y.Multiply(Y, &t) // y = Y/Z

	t.Subtract(_1, &y)
	t.Invert(&t)
	u.Add(_1, &y)
	u.Multiply(&u, &t) // u = (1+y)/(1-y)

	t.Invert(&x)
	v.Multiply(sqrt486664, &u)
	v.Multiply(&v, &t) // v = sqrt(-486664)*u/x

	return &point{x: u, y: v}
}

// https://www.rfc-editor.org/rfc/rfc7748.html#section-4.1
// (x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))
func edwardsFromMontgomery(m *point) *edwards25519.Point {
	var x, y, u, v, t field.Element

	u.Set(&m.x)
	v.Set(&m.y)

	t.Invert(&v)
	x.Multiply(sqrt486664, &u)
	x.Multiply(&x, &t) // x = sqrt(-486664)*u/v

	t.Add(&u, _1)
	t.Invert(&t)
	y.Subtract(&u, _1)
	y.Multiply(&y, &t) // y = (u-1)/(u+1)

	ex, _ := new(edfield.Element).SetBytes(x.Bytes())
	ey, _ := new(edfield.Element).SetBytes(y.Bytes())
	ez, _ := new(edfield.Element).SetBytes(_1.Bytes())
	et, _ := new(edfield.Element).SetBytes(t.Multiply(&x, &y).Bytes())
	p, err := new(edwards25519.Point).SetExtendedCoordinates(ex, ey, ez, et)
	if err != nil {
		panic(err)
	}
	return p
}
