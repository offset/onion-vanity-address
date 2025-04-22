package vanity25519_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/offset/onion-vanity-address/internal/vanity25519"
)

func ExampleSearch() {
	startKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	startPublicKey := startKey.PublicKey().Bytes()

	prefix, _ := base64.StdEncoding.DecodeString("AY/" + "x") // pad to 4 characters to decode properly
	testPrefix := vanity25519.HasPrefixBits(prefix, 3*6)      // search for 3-character prefix, i.e. 18 bits

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var found *big.Int

	attempts := vanity25519.Search(ctx, startPublicKey, big.NewInt(0), 4096, testPrefix, func(_ []byte, offset *big.Int) {
		found = offset
		cancel()
	})

	vkb, _ := vanity25519.Add(startKey.Bytes(), found)
	vk, _ := ecdh.X25519().NewPrivateKey(vkb)

	vpk := base64.StdEncoding.EncodeToString(vk.PublicKey().Bytes())

	fmt.Fprintf(os.Stderr, "Found %s after %d attempts\n", vpk, attempts)

	fmt.Printf("Found key: %s...\n", vpk[:3])
	// Output:
	// Found key: AY/...
}

func ExampleSearch_parallel() {
	startKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	startPublicKey := startKey.PublicKey().Bytes()

	prefix, _ := base64.StdEncoding.DecodeString("AY/" + "x") // pad to 4 characters to decode properly
	testPrefix := vanity25519.HasPrefixBits(prefix, 3*6)      // search for 3-character prefix, i.e. 18 bits

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var attempts atomic.Uint64
	var found atomic.Pointer[big.Int]

	var wg sync.WaitGroup
	for range runtime.NumCPU() {
		wg.Add(1)
		go func() {
			defer wg.Done()

			skip, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(1<<64-1))
			n := vanity25519.Search(ctx, startPublicKey, skip, 4096, testPrefix, func(_ []byte, offset *big.Int) {
				if found.CompareAndSwap(nil, offset) {
					cancel()
				}
			})
			attempts.Add(n)
		}()
	}
	wg.Wait()

	vkb, _ := vanity25519.Add(startKey.Bytes(), found.Load())
	vk, _ := ecdh.X25519().NewPrivateKey(vkb)

	vpk := base64.StdEncoding.EncodeToString(vk.PublicKey().Bytes())

	fmt.Fprintf(os.Stderr, "Found %s after %d attempts\n", vpk, attempts.Load())

	fmt.Printf("Found key: %s...\n", vpk[:3])
	// Output:
	// Found key: AY/...
}
