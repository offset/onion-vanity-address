package main

import (
	"bytes"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	hostnameFileName    = "hostname"
	publicKeyFileName   = "hs_ed25519_public_key"
	secretKeyFileName   = "hs_ed25519_secret_key"
	publicKeyFilePrefix = "== ed25519v1-public: type0 ==\x00\x00\x00"
	secretKeyFilePrefix = "== ed25519v1-secret: type0 ==\x00\x00\x00"
	secretKeyFileLength = 96
)

const onionBase32EncodingCharset = "abcdefghijklmnopqrstuvwxyz234567"

var onionBase32Encoding = base32.NewEncoding(onionBase32EncodingCharset).WithPadding(base32.NoPadding)

// encodeOnionAddress returns the .onion address for the given ed25519 public key,
// as specified in 6. Encoding onion addresses [ONIONADDRESS]
//
// [ONIONADDRESS] https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt
func encodeOnionAddress(publicKey []byte) string {
	version := []byte("\x03")

	// CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(publicKey)
	h.Write(version)
	checksum := h.Sum(nil)[:2]

	// onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
	var buf bytes.Buffer
	buf.Write(publicKey)
	buf.Write(checksum)
	buf.Write(version)

	return onionBase32Encoding.EncodeToString(buf.Bytes()) + ".onion"
}

func readServiceSecretKey(r io.Reader) ([]byte, error) {
	limit := int64(base64.StdEncoding.EncodedLen(secretKeyFileLength))
	encoded, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return nil, err
	}
	decoded := make([]byte, secretKeyFileLength)
	if _, err := base64.StdEncoding.Decode(decoded, encoded); err != nil {
		return nil, err
	}
	return parseServiceSecretKey(decoded)
}

// parseServiceSecretKey parses the content of hs_ed25519_secret_key file and returns the edwards25519 private key.
func parseServiceSecretKey(b []byte) ([]byte, error) {
	b, ok := bytes.CutPrefix(b, []byte(secretKeyFilePrefix))
	if !ok {
		return nil, fmt.Errorf("invalid secret key prefix")
	}
	if len(b) != 64 {
		return nil, fmt.Errorf("invalid secret key length, must be 64 bytes")
	}
	return b[:32], nil
}

func decodeServicePublicKey(from string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(from)
	if err != nil {
		return nil, err
	}
	return parseServicePublicKey(decoded)
}

// parseServicePublicKey parses the content of hs_ed25519_public_key file and returns the edwards25519 public key.
func parseServicePublicKey(b []byte) ([]byte, error) {
	b, ok := bytes.CutPrefix(b, []byte(publicKeyFilePrefix))
	if !ok {
		return nil, fmt.Errorf("invalid public key prefix")
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("invalid public key length, must be 32 bytes")
	}
	return b, nil
}

func encodeServicePublicKey(publicKey []byte) string {
	return base64.StdEncoding.EncodeToString(serializeServicePublicKey(publicKey))
}

// serializeServicePublicKey returns the content of hs_ed25519_public_key file.
func serializeServicePublicKey(publicKey []byte) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, publicKeyFilePrefix...)
	buf = append(buf, publicKey...)
	return buf
}

func encodeServiceSecretKey(publicKey []byte) string {
	return base64.StdEncoding.EncodeToString(serializeServiceSecretKey(publicKey))
}

// serializeServiceSecretKey returns the content of hs_ed25519_secret_key file.
func serializeServiceSecretKey(secretKey []byte) []byte {
	buf := make([]byte, 0, 96)
	buf = append(buf, secretKeyFilePrefix...)

	// From https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/lib/crypt_ops/crypto_ed25519.h#L27
	//
	//  * Note that we store secret keys in an expanded format that doesn't match
	//  * the format from standard ed25519.  Ed25519 stores a 32-byte value k and
	//  * expands it into a 64-byte H(k), using the first 32 bytes for a multiplier
	//  * of the base point, and second 32 bytes as an input to a hash function
	//  * for deriving r.  But because we implement key blinding, we need to store
	//  * keys in the 64-byte expanded form.
	//
	// Here we hash the secret key to deterministically get the second 32 bytes.
	// Tor also apparently does not clamp private key so do it here as well.
	hs := sha512.Sum512(secretKey)
	copy(hs[:], secretKey)
	hs[0] &= 248
	hs[31] &= 63
	hs[31] |= 64
	buf = append(buf, hs[:]...)
	return buf
}
