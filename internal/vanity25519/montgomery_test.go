package vanity25519

import (
	"fmt"
	"testing"

	"github.com/offset/onion-vanity-address/internal/edwards25519"
	"github.com/offset/onion-vanity-address/internal/vanity25519/field"
	"github.com/offset/onion-vanity-address/internal/vanity25519/internal/assert"
)

var (
	scalar3 = scalarFromUint64(3)
	scalar5 = scalarFromUint64(5)
	scalar8 = scalarFromUint64(8)

	edwards3 = edwards25519.NewGeneratorPoint().ScalarBaseMult(scalar3)
	edwards5 = edwards25519.NewGeneratorPoint().ScalarBaseMult(scalar5)
	edwards8 = new(edwards25519.Point).Add(edwards3, edwards5)
	edwards2 = new(edwards25519.Point).Subtract(edwards5, edwards3)
)

func (m *point) String() string {
	return fmt.Sprintf("{x: %x, y: %x}", m.x.Bytes(), m.y.Bytes())
}

func TestMontgomeryFromEdwards(t *testing.T) {
	g := edwards25519.NewGeneratorPoint()

	b := montgomeryFromEdwards(g)
	t.Log(b)

	assert.Equal(t, _B.x.Bytes(), b.x.Bytes())
	assert.Equal(t, _B.y.Bytes(), b.y.Bytes())
}

func TestEdwardsFromMontgomery(t *testing.T) {
	g := edwards25519.NewGeneratorPoint()

	b := edwardsFromMontgomery(_B)
	t.Log(b)

	assert.Equal(t, 1, g.Equal(b))
}

func TestAddX(t *testing.T) {
	expectedU := edwards8.BytesMontgomery()
	t.Logf("Expected u-coordinate: %x", expectedU)

	montgomery3 := montgomeryFromEdwards(edwards3)
	montgomery5 := montgomeryFromEdwards(edwards5)

	var x3 field.Element
	addX(&x3, montgomery3, montgomery5)
	t.Logf("Calculated x3: %x", x3.Bytes())

	assert.Equal(t, expectedU, x3.Bytes())
}

func TestAddY(t *testing.T) {
	expectedV := montgomeryFromEdwards(edwards8).y
	t.Logf("Expected v-coordinate: %x", expectedV.Bytes())

	montgomery3 := montgomeryFromEdwards(edwards3)
	montgomery5 := montgomeryFromEdwards(edwards5)

	var y3 field.Element
	addY(&y3, montgomery3, montgomery5)
	t.Logf("Calculated y3: %x", y3.Bytes())

	assert.Equal(t, expectedV.Bytes(), y3.Bytes())
}

func TestAdd(t *testing.T) {
	expectedMontgomery8 := montgomeryFromEdwards(edwards8)

	montgomery3 := montgomeryFromEdwards(edwards3)
	montgomery5 := montgomeryFromEdwards(edwards5)
	got := new(point).add(montgomery3, montgomery5)

	t.Log(got)

	assert.Equal(t, expectedMontgomery8.x.Bytes(), got.x.Bytes())
	assert.Equal(t, expectedMontgomery8.y.Bytes(), got.y.Bytes())
}

func TestAddAlias(t *testing.T) {
	expectedMontgomery8 := montgomeryFromEdwards(edwards8)

	montgomery3 := montgomeryFromEdwards(edwards3)
	montgomery5 := montgomeryFromEdwards(edwards5)
	p := montgomery3
	got := p.add(p, montgomery5)

	t.Log(got)

	assert.Equal(t, expectedMontgomery8.x.Bytes(), got.x.Bytes())
	assert.Equal(t, expectedMontgomery8.y.Bytes(), got.y.Bytes())
}

func TestSub(t *testing.T) {
	expectedMontgomery2 := montgomeryFromEdwards(edwards2)

	montgomery3 := montgomeryFromEdwards(edwards3)
	montgomery5 := montgomeryFromEdwards(edwards5)
	montgomery3.y.Negate(&montgomery3.y) // Negate y to match the subtraction
	got := new(point).add(montgomery5, montgomery3)

	t.Log(got)

	assert.Equal(t, expectedMontgomery2.x.Bytes(), got.x.Bytes())
	assert.Equal(t, expectedMontgomery2.y.Bytes(), got.y.Bytes())
}

func TestDouble(t *testing.T) {
	edwards6 := new(edwards25519.Point).Double(edwards3)

	montgomery3 := montgomeryFromEdwards(edwards3)
	montgomery6 := new(point).double(montgomery3)

	expectedMontgomery6 := montgomeryFromEdwards(edwards6)

	t.Logf("Expected Montgomery 6: %s", expectedMontgomery6)
	t.Logf("Calculated Montgomery 6: %s", montgomery6)

	assert.Equal(t, expectedMontgomery6.x.Bytes(), montgomery6.x.Bytes())
	assert.Equal(t, expectedMontgomery6.y.Bytes(), montgomery6.y.Bytes())
}

func TestDoubleAlias(t *testing.T) {
	expectedMontgomery2 := montgomeryFromEdwards(edwards2)

	montgomery2 := new(point).set(_B)
	montgomery2.double(montgomery2)

	assert.Equal(t, expectedMontgomery2.x.Bytes(), montgomery2.x.Bytes())
	assert.Equal(t, expectedMontgomery2.y.Bytes(), montgomery2.y.Bytes())
}

func TestB8(t *testing.T) {
	edwardsB8 := edwards25519.NewGeneratorPoint().ScalarBaseMult(scalar8)

	expectedMontgomeryB8 := montgomeryFromEdwards(edwardsB8)

	t.Logf("Expected Montgomery B8: %s", expectedMontgomeryB8)
	t.Logf("Calculated Montgomery B8: %s", _B8)

	assert.Equal(t, expectedMontgomeryB8.x.Bytes(), _B8.x.Bytes())
	assert.Equal(t, expectedMontgomeryB8.y.Bytes(), _B8.y.Bytes())
}

func TestSetBytes(t *testing.T) {
	expectedY := new(field.Element).Set(&_B.y)
	if expectedY.IsNegative() == 1 {
		expectedY.Negate(expectedY)
	}

	p, err := new(point).setBytes(_B.x.Bytes())
	assert.NoError(t, err)
	assert.Equal(t, _B.x.Bytes(), p.x.Bytes())
	assert.Equal(t, expectedY.Bytes(), p.y.Bytes())
}
