package vanity25519

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/offset/onion-vanity-address/internal/edwards25519"
	"github.com/offset/onion-vanity-address/internal/vanity25519/field"
	"github.com/offset/onion-vanity-address/internal/vanity25519/internal/assert"
	"github.com/offset/onion-vanity-address/internal/vanity25519/internal/require"
)

func TestMakeOffsets(t *testing.T) {
	const n = 1024

	offsets := makeOffsets(n)
	for i := range n {
		expectedEdwards := edwards25519.NewGeneratorPoint().ScalarBaseMult(scalarFromUint64(uint64(i+1) * 8))
		expectedMontgomery := montgomeryFromEdwards(expectedEdwards)

		assert.Equal(t, expectedMontgomery.x.Bytes(), offsets[i].x.Bytes())
		assert.Equal(t, expectedMontgomery.y.Bytes(), offsets[i].y.Bytes())
	}
}

func TestInvert(t *testing.T) {
	for _, n := range []int{1, 2, 10, 100, 1000} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			var buf [32]byte

			a := make([]field.Element, n)
			s := make([]field.Element, n)
			e := make([]field.Element, n)
			for i := range n {
				rand.Read(buf[:])
				a[i] = *fieldElementFromBytes(buf[:])

				e[i].Invert(&a[i])
			}

			invert(a, s)

			for i := range n {
				assert.Equal(t, e[i].Bytes(), a[i].Bytes())
			}
		})
	}
}

func TestAddXBatch(t *testing.T) {
	const n = 1024

	edwardsP1 := edwards25519.NewGeneratorPoint()
	expectedX := make([]field.Element, 2*n)
	for i := range n {
		oi := new(edwards25519.Point).ScalarBaseMult(scalarFromUint64(uint64(8 * (i + 1))))

		pp := new(edwards25519.Point).Add(edwardsP1, oi)
		expectedX[i].SetBytes(pp.BytesMontgomery())

		pm := new(edwards25519.Point).Subtract(edwardsP1, oi)
		expectedX[n+i].SetBytes(pm.BytesMontgomery())
	}

	x := make([]field.Element, 2*n)
	dx := make([]field.Element, n+1)

	p1 := _B
	dxInv := fieldElementFromUint64(123456789)
	dxInvExpectedBytes := new(field.Element).Invert(dxInv).Bytes()

	dx[n].Set(dxInv)

	addXBatch(p1, makeOffsets(n), dx, x)

	for i := range x {
		assert.Equal(t, expectedX[i].Bytes(), x[i].Bytes())
	}
	assert.Equal(t, dxInvExpectedBytes, dx[n].Bytes())
}

func TestSearch(t *testing.T) {
	t.Run("qkHBetbXfAxsmr0jH6Zs6Dx1ZEReO9WBZCoNREce0gE=", func(t *testing.T) {
		const k = "qkHBetbXfAxsmr0jH6Zs6Dx1ZEReO9WBZCoNREce0gE="

		kb, err := base64.StdEncoding.DecodeString(k)
		require.NoError(t, err)

		expectedOffset := big.NewInt(92950)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		accept := HasPrefixBits(decodeBase64PrefixBits("AY/"))

		var found *big.Int
		yield := func(_ []byte, offset *big.Int) {
			found = offset
			cancel()
		}

		Search(ctx, kb, big.NewInt(0), 8, accept, yield)

		assert.Equal(t, expectedOffset, found)

		p, err := edwardsPointFromMontgomeryBytes(kb)
		require.NoError(t, err)

		po := new(edwards25519.Point).ScalarBaseMult(scalarFromBigInt(found))
		po.MultByCofactor(po)
		p.Add(p, po)

		assert.Equal(t, "AY/yq7zukqRmMUzqqPFmtqXJdAcbmh8mn4rMgtjVnGI=", base64.StdEncoding.EncodeToString(p.BytesMontgomery()))
	})

	acceptAll := func(_ []byte) bool { return true }

	t.Run("1000", func(t *testing.T) {
		const n = 1000
		const sk = "iIONKxNiB8wkVEO7oneDlI3sktmfsS1p4wQDrzBhRlo="
		const pk = "2U15Ir9CYFkGDAOtgsqWagSa+RKdXCHqjKm0kPkwm20="

		skb, err := base64.StdEncoding.DecodeString(sk)
		require.NoError(t, err)

		pkb, err := base64.StdEncoding.DecodeString(pk)
		require.NoError(t, err)

		k, err := ecdh.X25519().NewPrivateKey(skb)
		require.NoError(t, err)
		assert.Equal(t, k.PublicKey().Bytes(), pkb)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		i := 0
		Search(ctx, pkb, big.NewInt(0), 8, acceptAll, func(xb []byte, offset *big.Int) {
			kb, err := Add(skb, offset)
			require.NoError(t, err)

			k, err := ecdh.X25519().NewPrivateKey(kb)
			assert.NoError(t, err)
			assert.Equal(t, k.PublicKey().Bytes(), xb)

			if i++; i == n {
				cancel()
			}
		})
	})

	t.Run("random", func(t *testing.T) {
		for range 100 {
			t.Run("", func(t *testing.T) {
				k, err := ecdh.X25519().GenerateKey(rand.Reader)
				require.NoError(t, err)
				skb := k.Bytes()
				pkb := k.PublicKey().Bytes()

				startOffset := new(big.Int).SetUint64(randUint64())
				t.Logf("Start offset: %16x", startOffset)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				i := 0
				Search(ctx, pkb, startOffset, 8, acceptAll, func(xb []byte, offset *big.Int) {
					kb, err := Add(skb, offset)
					require.NoError(t, err)

					k, err = ecdh.X25519().NewPrivateKey(kb)
					assert.NoError(t, err)
					assert.Equal(t, k.PublicKey().Bytes(), xb)

					if i++; i == 100 {
						cancel()
					}
				})
			})
		}
	})
}

func BenchmarkSearch(b *testing.B) {
	testPrefix := HasPrefixBits(decodeBase64PrefixBits("GoodLuckWithThisPrefix"))

	for _, batchSize := range []int{
		2, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
	} {
		b.Run(fmt.Sprintf("%d", batchSize), func(b *testing.B) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			i := 0
			Search(ctx, _B.x.Bytes(), big.NewInt(0), batchSize, func(candidatePublicKey []byte) bool {
				_ = testPrefix(candidatePublicKey)
				if i++; i == b.N {
					cancel()
				}
				return false
			}, nil)
		})
	}
}

func BenchmarkSearchParallel(b *testing.B) {
	testPrefix := HasPrefixBits(decodeBase64PrefixBits("GoodLuckWithThisPrefix"))

	for _, batchSize := range []int{1024, 2048, 4096, 8192, 16384} {
		b.Run(fmt.Sprintf("%d", batchSize), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				Search(ctx, _B.x.Bytes(), new(big.Int).SetUint64(randUint64()), batchSize, func(candidatePublicKey []byte) bool {
					_ = testPrefix(candidatePublicKey)
					if !pb.Next() {
						cancel()
					}
					return false
				}, nil)
			})
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "keys/s")
		})
	}
}

var sink uint64

func BenchmarkDoneContext(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b.RunParallel(func(pb *testing.PB) {
		var c uint64
		for pb.Next() {
			select {
			case <-ctx.Done():
			default:
				c++
			}
		}
		sink += c
	})
}

func BenchmarkDoneAtomicBool(b *testing.B) {
	var done atomic.Bool

	b.RunParallel(func(pb *testing.PB) {
		var c uint64
		for pb.Next() {
			if !done.Load() {
				c++
			}
		}
		sink += c
	})
}
