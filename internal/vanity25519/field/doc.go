// Package field implements fast arithmetic modulo 2^255-19.
//
// [Element] type API is the same as [github.com/offset/onion-vanity-address/internal/edwards25519/field.Element].
//
// Performance:
// The package uses optimized assembly implementations translated from
// Amazon's [s2n-bignum] library for
// arithmetic operations on amd64 and arm64 architectures, providing
// performance improvement over [github.com/offset/onion-vanity-address/internal/edwards25519/field] implementation.
//
// The Go assembly files are translated from s2n-bignum's proven
// assembly implementations and verified by comparing the disassembled machine code
// output from the Go compiler against the original s2n-bignum implementations.
//
// [s2n-bignum]: https://github.com/awslabs/s2n-bignum
package field
