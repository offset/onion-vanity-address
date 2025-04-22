package main

import (
	"testing"

	"github.com/offset/onion-vanity-address/internal/assert"
)

func TestDecodePrefixBits(t *testing.T) {
	tests := []struct {
		input         string
		expectedBytes []byte
		expectedBits  int
	}{
		{
			input:         "7",
			expectedBytes: []byte{0b11111_000, 0, 0, 0, 0},
			expectedBits:  5,
		},
		{
			input:         "77",
			expectedBytes: []byte{0b11111_111, 0b11_00000_0, 0, 0, 0},
			expectedBits:  10,
		},
		{
			input:         "b",
			expectedBytes: []byte{0b00001_000, 0, 0, 0, 0},
			expectedBits:  5,
		},
		{
			input:         "ay",
			expectedBytes: []byte{0b00000_110, 0b00_00000_0, 0, 0, 0},
			expectedBits:  10,
		},
		{
			input:         "abc",
			expectedBytes: []byte{0b00000_000, 0b01_00010_0, 0, 0, 0},
			expectedBits:  15,
		},
		{
			input:         "ayay",
			expectedBytes: []byte{0b00000_110, 0b00_00000_1, 0b1000_0000, 0, 0},
			expectedBits:  20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			b, n, err := decodePrefixBits(tt.input, onionBase32Encoding)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBits, n)
			assert.Equal(t, tt.expectedBytes, b)
		})
	}
}
