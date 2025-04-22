package main

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"strings"
)

type prefixMatchFunc func(string) (func([]byte) bool, error)

func matchAnyOf(prefixes []string, match prefixMatchFunc) (func([]byte) bool, error) {
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("at least one prefix required")
	}

	if len(prefixes) == 1 {
		return match(prefixes[0])
	}

	tests := make([]func([]byte) bool, len(prefixes))
	for i, p := range prefixes {
		var err error
		tests[i], err = match(p)
		if err != nil {
			return nil, err
		}
	}

	return func(p []byte) bool {
		for _, test := range tests {
			if test(p) {
				return true
			}
		}
		return false
	}, nil
}

// hasPrefix returns a function that checks if the input has the specified encoded prefix.
func hasPrefix(prefix string, enc *base32.Encoding) (func(input []byte) bool, error) {
	prefixBytes, bits, err := decodePrefixBits(prefix, enc)
	if err != nil {
		return nil, err
	}
	return hasPrefixBits(prefixBytes, bits), nil
}

// decodePrefixBits returns base32-decoded prefix and number of decoded bits.
func decodePrefixBits(prefix string, enc *base32.Encoding) ([]byte, int, error) {
	decodedBits := 5 * len(prefix)
	quantums := (len(prefix) + 7) / 8
	zeroChar := enc.EncodeToString([]byte{0})[0:1]
	prefix += strings.Repeat(zeroChar, quantums*8-len(prefix))
	buf := make([]byte, quantums*5)
	_, err := enc.Decode(buf, []byte(prefix))
	if err != nil {
		return nil, 0, err
	}
	return buf, decodedBits, err
}

// hasPrefixBits returns a function that checks if the input has the specified prefix bits.
func hasPrefixBits(prefix []byte, bits int) func(input []byte) bool {
	if len(prefix) == 0 || len(prefix) > 32 {
		panic("invalid prefix")
	}
	if bits <= 0 || bits > 256 || bits > len(prefix)*8 {
		panic("invalid bits")
	}

	if bits%8 == 0 {
		return func(b []byte) bool {
			return bytes.HasPrefix(b, prefix)
		}
	}

	prefixBytes := bits / 8
	shift := 8 - (bits % 8)
	tailByte := prefix[prefixBytes] >> shift
	prefix = prefix[:prefixBytes]

	return func(b []byte) bool {
		return len(b) > prefixBytes && // must be long enough to check tail byte
			bytes.Equal(b[:prefixBytes], prefix) &&
			b[prefixBytes]>>shift == tailByte
	}
}

func longestMatching(prefixes []string, value string) string {
	longest := ""
	for _, p := range prefixes {
		if strings.HasPrefix(value, p) && len(p) > len(longest) {
			longest = p
		}
	}
	if longest == "" {
		panic("no matching prefix")
	}
	return longest
}
