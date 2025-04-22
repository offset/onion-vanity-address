# vanity25519 [![Go Reference](https://pkg.go.dev/badge/github.com/AlexanderYastrebov/vanity25519.svg)](https://pkg.go.dev/github.com/AlexanderYastrebov/vanity25519)

This package implements an efficient [curve25519](https://datatracker.ietf.org/doc/html/rfc7748#section-4.1) vanity key generator.

This package provides functions to generate vanity curve25519 key pair with a specific pattern in its public key.
It uses an optimized search algorithm that generates candidate public keys by adding offsets to the start public key,
avoiding the need to perform full scalar multiplication for each candidate.

The algorithm has amortized cost **(3.5M + 3A)** per candidate key, where M is field multiplication and A is field addition.

For comparison, brute-force key pair generator requires
**2561** field multiplications using [double-and-add](https://github.com/golang/go/commit/e005cdc62081130117a3fa30d01cd28ee076ed93) or
**743** field multiplications using [Twisted Edwards curve](https://github.com/FiloSottile/edwards25519/commit/2941d4c8cdacb392a1b39f85adafaeae65bb50f6) per candidate key.

See [example_test.go](example_test.go) for usage.

## Tools

* [wireguard-vanity-key](https://github.com/AlexanderYastrebov/wireguard-vanity-key) — Fast WireGuard vanity key generator.
* [age-vanity-keygen](https://github.com/AlexanderYastrebov/age-vanity-keygen) — Fast vanity age X25519 identity generator.
* [onion-vanity-address](https://github.com/AlexanderYastrebov/onion-vanity-address) — Fast Tor Onion Service vanity address generator.
