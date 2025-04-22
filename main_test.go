package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/offset/onion-vanity-address/internal/assert"
	"github.com/offset/onion-vanity-address/internal/require"
)

func TestFixture(t *testing.T) {
	const fixture = "onionjifniegtjbbifet65goa2siqubne6n2qfhiksryfvsbdhdl5zid.onion"

	secretKeyBytes, err := os.ReadFile(filepath.Join("testdata", fixture, "hs_ed25519_secret_key"))
	require.NoError(t, err)

	secretKeyBytes = bytes.TrimPrefix(secretKeyBytes, []byte(secretKeyFilePrefix))
	require.Equal(t, 64, len(secretKeyBytes))

	publicKeyBytes, err := os.ReadFile(filepath.Join("testdata", fixture, "hs_ed25519_public_key"))
	require.NoError(t, err)

	expectedPublicKey := bytes.TrimPrefix(publicKeyBytes, []byte(publicKeyFilePrefix))
	require.Equal(t, 32, len(expectedPublicKey))

	secretKey := secretKeyBytes[:32]
	t.Logf("Secret key: %s", onionBase32Encoding.EncodeToString(secretKey))

	publicKey, err := publicKeyFor(secretKey)
	require.NoError(t, err)

	t.Logf("Public key: %s", onionBase32Encoding.EncodeToString(publicKey))

	assert.Equal(t, expectedPublicKey, publicKey)

	onionAddress := encodeOnionAddress(publicKey)
	assert.Equal(t, fixture, onionAddress)

	hostnameBytes, err := os.ReadFile(filepath.Join("testdata", fixture, "hostname"))
	require.NoError(t, err)

	assert.Equal(t, []byte(fixture+"\n"), hostnameBytes)
}
