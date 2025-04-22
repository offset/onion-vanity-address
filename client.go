package main

import (
	"encoding/base32"
	"fmt"
	"io"

	"github.com/offset/onion-vanity-address/internal/edwards25519"
)

const clientBase32EncodingCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

var clientBase32Encoding = base32.NewEncoding(clientBase32EncodingCharset).WithPadding(base32.NoPadding)

func readClientSecretKey(r io.Reader) ([]byte, error) {
	limit := int64(clientBase32Encoding.EncodedLen(32))
	encoded, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return nil, err
	}
	decoded := make([]byte, 32)
	_, err = clientBase32Encoding.Decode(decoded, encoded)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func decodeClientPublicKey(s string) ([]byte, error) {
	key, err := clientBase32Encoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid public key length, must be 32 bytes")
	}
	return key, nil
}

func clientPublicKeyFor(privateKey []byte) ([]byte, error) {
	s, err := new(edwards25519.Scalar).SetBytesWithClamping(privateKey)
	if err != nil {
		return nil, err
	}
	return new(edwards25519.Point).ScalarBaseMult(s).BytesMontgomery(), nil
}
