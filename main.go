package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/offset/onion-vanity-address/internal/vanity25519"
)

const usage = `Usage:
    onion-vanity-address [--client] [--from PUBLIC_KEY] [--timeout TIMEOUT] PREFIX [PREFIX]...
    onion-vanity-address [--client] --offset OFFSET

Options:
    --client                Search for a Client Authorization keypair instead of an Onion Service keypair.
    --from PUBLIC_KEY       Start search from the given public key.
    --offset OFFSET         Add an offset to the secret keys read from standard input.
    --timeout TIMEOUT       Stop after the specified timeout (e.g., 10s, 5m, 1h).

onion-vanity-address generates a new Onion Service ed25519 keypair with an onion address having one of the specified PREFIXes,
and outputs it to standard output in base64-encoded YAML format.

In --client mode, onion-vanity-address generates a Client Authorization keypair with public key having one of the specified PREFIXes.

PREFIX must use base32 character set "` + onionBase32EncodingCharset + `" for Onion Service keypair
and "` + clientBase32EncodingCharset + `" for Client Authorization keypair.

In --from mode, onion-vanity-address starts the search from a specified public key and
outputs the offset to the public key with the desired prefix.
The offset can be added to the corresponding secret key to derive the new keypair.

In --offset mode, onion-vanity-address reads the secret key from standard input,
adds the specified offset to it, and outputs the resulting keypair.

Service examples:

    # Generate a new service keypair with address having the specified prefix
    $ onion-vanity-address allium
    Found allium... in 12s after 558986486 attempts (48529996 attempts/s)
    ---
    hostname: alliumdye3it7ko4cuftoni4rlrupuobvio24ypz55qpzjzpvuetzhyd.onion
    hs_ed25519_public_key: PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAAAC1ooweCbRP6ncFQs3NRyK40fRwaodrmH572D8py+tCQ==
    hs_ed25519_secret_key: PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAAAQEW4Rhot7oroPaETlAEG3GPAntvJ1agF2c7A2AXmBW3WqAH0oUZ1hySvvZl3hc9dSAIc49h1UuCPZacOWp4vQ

    # Find prefix offset from the specified public key
    $ onion-vanity-address --from PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAAAC1ooweCbRP6ncFQs3NRyK40fRwaodrmH572D8py+tCQ== cebula
    Found cebula... in 2s after 78457550 attempts (44982483 attempts/s)
    ---
    hostname: cebulasfa3b4ahol44ydvc2an6b4vgpjcguarwsj35dr6jbanveea4id.onion
    offset: cIZ5Birj/cY=

    # Apply offset to the secret key
    $ echo PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAAAQEW4Rhot7oroPaETlAEG3GPAntvJ1agF2c7A2AXmBW3WqAH0oUZ1hySvvZl3hc9dSAIc49h1UuCPZacOWp4vQ \
    | onion-vanity-address --offset cIZ5Birj/cY=
    ---
    hostname: cebulasfa3b4ahol44ydvc2an6b4vgpjcguarwsj35dr6jbanxenrcqd.onion
    hs_ed25519_public_key: PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAAARA0WCRQbDwB3L5zA6i0Bvg8qZ6RGoCNpJ30cfJCBtyA==
    hs_ed25519_secret_key: PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAABA/41ot1OvJr4PaETlAEG3GPAntvJ1agF2c7A2AXmBW/BnbLk2LgY3abEydc7heS5rhKByW/nafTlwifcgL0zO

Client examples:

    # Generate a new client authorization keypair with the specified prefix
    $ onion-vanity-address --client LEMON
    Found LEMON... in 0s after 14990923 attempts (63626192 attempts/s)
    ---
    public_key: LEMON7P5L7FEZZEJJGQTC3PDFRHEOOBP3H2XXHRFQSD72OKKEE5Q
    private_key: AAADDFICRR46KLA52KV2QRIN6GUWIPEIVZZZUVZLC5UVE53QNMTA

    # Find prefix offset from the specified public key
    $ onion-vanity-address --client --from LEMON7P5L7FEZZEJJGQTC3PDFRHEOOBP3H2XXHRFQSD72OKKEE5Q TOMATO
    Found TOMATO... in 16s after 1071246687 attempts (65052983 attempts/s)
    ---
    public_key: TOMATOWHTLC3ERVBD2D6V5DENSWPBAHYUKJNYNUALO3CJB2C2BZQ
    offset: 0mtckGJcwbs=

    # Apply offset to the private key
    $ echo AAADDFICRR46KLA52KV2QRIN6GUWIPEIVZZZUVZLC5UVE53QNMTA | onion-vanity-address --client --offset 0mtckGJcwbs=
    ---
    public_key: TOMATOWHTLC3ERVBD2D6V5DENSWPBAHYUKJNYNUALO3CJB2C2BZQ
    private_key: FDZEVAT7U4PFEJQ52KV2QRIN6GUWIPEIVZZZUVZLC5UVE53QNMTA
`

func must[T any](v T, err error) T {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return v
}

func check(cond bool, msg string) {
	if !cond {
		fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
		flag.Usage()
		os.Exit(1)
	}
}

func main() {
	var clientFlag bool
	var fromFlag string
	var offsetFlag string
	var timeoutFlag time.Duration

	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.BoolVar(&clientFlag, "client", false, "search for a Client Authorization keypair instead of an Onion Service keypair")
	flag.StringVar(&fromFlag, "from", "", "public key to start search from")
	flag.StringVar(&offsetFlag, "offset", "", "offset to add to the secret key read from stdin")
	flag.DurationVar(&timeoutFlag, "timeout", 0, "stop after specified timeout")
	flag.Parse()

	if offsetFlag != "" {
		check(fromFlag == "", "--from can not be used with --offset")
		check(timeoutFlag == 0, "--timeout can not be used with --offset")
		check(flag.NArg() == 0, "PREFIX can not be used with --offset")

		offset := new(big.Int).SetBytes(must(base64.StdEncoding.DecodeString(offsetFlag)))

		if clientFlag {
			offsetClientKey(offset)
		} else {
			offsetServiceKey(offset)
		}
		return
	}

	check(flag.NArg() > 0, "PREFIX required")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if timeoutFlag > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeoutFlag)
		defer cancel()
	}

	if clientFlag {
		searchClientKey(ctx, flag.Args(), fromFlag)
	} else {
		searchServiceKey(ctx, flag.Args(), fromFlag)
	}
}

func offsetClientKey(offset *big.Int) {
	startSecretKey := must(readClientSecretKey(os.Stdin))
	vanitySecretKey := must(vanity25519.Add(startSecretKey, offset))
	vanityPublicKey := must(clientPublicKeyFor(vanitySecretKey))

	fmt.Println("---")
	fmt.Printf("public_key: %s\n", clientBase32Encoding.EncodeToString(vanityPublicKey))
	fmt.Printf("private_key: %s\n", clientBase32Encoding.EncodeToString(vanitySecretKey))
}

func offsetServiceKey(offset *big.Int) {
	startSecretKey := must(readServiceSecretKey(os.Stdin))
	vanitySecretKey := must(add(startSecretKey, offset))
	vanityPublicKey := must(publicKeyFor(vanitySecretKey))

	fmt.Println("---")
	fmt.Printf("%s: %s\n", hostnameFileName, encodeOnionAddress(vanityPublicKey))
	fmt.Printf("%s: %s\n", publicKeyFileName, encodeServicePublicKey(vanityPublicKey))
	fmt.Printf("%s: %s\n", secretKeyFileName, encodeServiceSecretKey(vanitySecretKey))
}

func searchClientKey(ctx context.Context, prefixes []string, from string) {
	var startSecretKey, startPublicKey []byte
	if from != "" {
		startPublicKey = must(decodeClientPublicKey(from))
	} else {
		startSecretKey = make([]byte, 32)
		rand.Read(startSecretKey)

		startPublicKey = must(clientPublicKeyFor(startSecretKey))
	}

	start := time.Now()
	found, vanityPublicKey, attempts := parallel(vanity25519.Search, ctx, startPublicKey, must(matchAnyOf(prefixes, clientMatch)))
	elapsed := time.Since(start)

	if found != nil {
		var vanitySecretKey []byte
		if len(startSecretKey) > 0 {
			vanitySecretKey = must(vanity25519.Add(startSecretKey, found))
			vanityPublicKey = must(clientPublicKeyFor(vanitySecretKey))
		}

		vanityPublicKeyEncoded := clientBase32Encoding.EncodeToString(vanityPublicKey)
		prefix := longestMatching(prefixes, vanityPublicKeyEncoded)

		fmt.Fprintf(os.Stderr, "Found %s... in %s after %d attempts (%.0f attempts/s)\n",
			prefix, elapsed.Round(time.Second), attempts, float64(attempts)/elapsed.Seconds())

		fmt.Println("---")
		fmt.Printf("public_key: %s\n", vanityPublicKeyEncoded)
		if len(vanitySecretKey) > 0 {
			fmt.Printf("private_key: %s\n", clientBase32Encoding.EncodeToString(vanitySecretKey))
		} else {
			fmt.Printf("offset: %s\n", base64.StdEncoding.EncodeToString(found.Bytes()))
		}
	} else {
		fmt.Fprintf(os.Stderr, "Stopped searching %v... after %s and %d attempts (%.0f attempts/s)\n",
			prefixes, elapsed.Round(time.Second), attempts, float64(attempts)/elapsed.Seconds())
		os.Exit(2)
	}
}

func searchServiceKey(ctx context.Context, prefixes []string, from string) {
	var startSecretKey, startPublicKey []byte
	if from != "" {
		startPublicKey = must(decodeServicePublicKey(from))
	} else {
		startSecretKey = make([]byte, 32)
		rand.Read(startSecretKey)

		startPublicKey = must(publicKeyFor(startSecretKey))
	}

	start := time.Now()
	found, vanityPublicKey, attempts := parallel(search, ctx, startPublicKey, must(matchAnyOf(prefixes, addressMatch)))
	elapsed := time.Since(start)

	if found != nil {
		var vanitySecretKey []byte
		if len(startSecretKey) > 0 {
			vanitySecretKey = must(add(startSecretKey, found))
			vanityPublicKey = must(publicKeyFor(vanitySecretKey))
		}

		address := encodeOnionAddress(vanityPublicKey)
		prefix := longestMatching(prefixes, address)

		fmt.Fprintf(os.Stderr, "Found %s... in %s after %d attempts (%.0f attempts/s)\n",
			prefix, elapsed.Round(time.Second), attempts, float64(attempts)/elapsed.Seconds())

		fmt.Println("---")
		fmt.Printf("%s: %s\n", hostnameFileName, address)
		if len(vanitySecretKey) > 0 {
			fmt.Printf("%s: %s\n", publicKeyFileName, encodeServicePublicKey(vanityPublicKey))
			fmt.Printf("%s: %s\n", secretKeyFileName, encodeServiceSecretKey(vanitySecretKey))
		} else {
			fmt.Printf("offset: %s\n", base64.StdEncoding.EncodeToString(found.Bytes()))
		}
	} else {
		fmt.Fprintf(os.Stderr, "Stopped searching %v... after %s and %d attempts (%.0f attempts/s)\n",
			prefixes, elapsed.Round(time.Second), attempts, float64(attempts)/elapsed.Seconds())
		os.Exit(2)
	}
}

func clientMatch(prefix string) (func([]byte) bool, error) {
	if len(prefix) == 0 {
		return nil, fmt.Errorf("empty prefix")
	}

	if strings.TrimLeft(prefix, clientBase32EncodingCharset) != "" {
		return nil, fmt.Errorf("client public key prefix must use characters %q", clientBase32EncodingCharset)
	}

	return hasPrefix(prefix, clientBase32Encoding)
}

func addressMatch(prefix string) (func([]byte) bool, error) {
	if len(prefix) == 0 {
		return nil, fmt.Errorf("empty prefix")
	}

	if strings.TrimLeft(prefix, onionBase32EncodingCharset) != "" {
		return nil, fmt.Errorf("address prefix must use characters %q", onionBase32EncodingCharset)
	}

	return hasPrefix(prefix, onionBase32Encoding)
}

type searchFunc func(ctx context.Context, startPublicKey []byte, startOffset *big.Int, batchSize int, accept func(candidatePublicKey []byte) bool, yield func(publicKey []byte, offset *big.Int)) uint64

func parallel(search searchFunc, ctx context.Context, startPublicKey []byte, test func([]byte) bool) (*big.Int, []byte, uint64) {
	var result atomic.Pointer[big.Int]
	var vanityPublicKey []byte

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var attemptsTotal atomic.Uint64
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			startOffset, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(1<<64-1))
			attempts := search(ctx, startPublicKey, startOffset, 4096, test, func(pk []byte, offset *big.Int) {
				if result.CompareAndSwap(nil, offset) {
					vanityPublicKey = pk
					cancel()
				}
			})
			attemptsTotal.Add(attempts)
		})
	}
	wg.Wait()

	return result.Load(), vanityPublicKey, attemptsTotal.Load()
}
