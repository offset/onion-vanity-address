package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/offset/onion-vanity-address/internal/edwards25519"
	"github.com/offset/onion-vanity-address/internal/assert"
	"github.com/offset/onion-vanity-address/internal/require"
)

func TestSearch(t *testing.T) {
	t.Run("onionjifniegtjbbifet65goa2siqubne6n2qfhiksryfvsbdhda", func(t *testing.T) {
		const sk = "7bd6z6w72afftbr7aybfbgstm7exdnndgm74cocbrnfkjegnifca"
		const pk = "onionjifniegtjbbifet65goa2siqubne6n2qfhiksryfvsbdhda"

		skb, err := onionBase32Encoding.DecodeString(sk)
		require.NoError(t, err)

		pkb, err := onionBase32Encoding.DecodeString(pk)
		require.NoError(t, err)
		p0, err := new(edwards25519.Point).SetBytes(pkb)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		accept, err := hasPrefix("ayay", onionBase32Encoding)
		require.NoError(t, err)

		var found *big.Int
		yield := func(publicKey []byte, offset *big.Int) {
			found = offset
			cancel()
		}

		search(ctx, p0.Bytes(), big.NewInt(0), 2, accept, yield)

		po := new(edwards25519.Point).ScalarMult(scalarFromBigInt(found), _B8)
		p := new(edwards25519.Point).Add(p0, po)

		vpk := onionBase32Encoding.EncodeToString(p.Bytes())
		t.Logf("vanity public key: %s at offest: %d", vpk, found)

		assert.True(t, strings.HasPrefix(vpk, "ayay"))

		vsk, err := add(skb, found)
		assert.NoError(t, err)

		vpk2, err := publicKeyFor(vsk)
		require.NoError(t, err)

		assert.Equal(t, vpk, onionBase32Encoding.EncodeToString(vpk2))
	})

	acceptAll := func(_ []byte) bool { return true }

	t.Run("random", func(t *testing.T) {
		for range 100 {
			t.Run("", func(t *testing.T) {
				pk, sk, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)

				hs := sha512.New()
				hs.Write(sk.Seed())
				skb := hs.Sum(nil)[:32]

				startOffset, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(1<<64-1))
				t.Logf("Start offset: %16x", startOffset)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				i := 0
				search(ctx, pk, startOffset, 8, acceptAll, func(xb []byte, offset *big.Int) {
					kb, err := add(skb, offset)
					require.NoError(t, err)

					pkb, err := publicKeyFor(kb)
					assert.NoError(t, err)

					// Check ignoring sign bit
					pkb[31] &= 0x7f
					assert.Equal(t, pkb, xb)

					if i++; i == 100 {
						cancel()
					}
				})
			})
		}
	})
}

func BenchmarkSearchParallel(b *testing.B) {
	startPublicKey, err := onionBase32Encoding.DecodeString("onionjifniegtjbbifet65goa2siqubne6n2qfhiksryfvsbdhda")
	require.NoError(b, err)

	testPrefix, err := hasPrefix("goodluckwiththisprefix", onionBase32Encoding)
	require.NoError(b, err)

	for _, batchSize := range []int{1024, 2048, 4096, 8192} {
		b.Run(fmt.Sprintf("%d", batchSize), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				startOffset, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(1<<64-1))
				search(ctx, startPublicKey, startOffset, batchSize, func(candidatePublicKey []byte) bool {
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
