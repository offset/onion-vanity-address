package vanity25519

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/offset/onion-vanity-address/internal/edwards25519"

	"github.com/offset/onion-vanity-address/internal/vanity25519/internal/assert"
)

func TestHasPrefixBits(t *testing.T) {
	t.Logf("AY/: % x", "AY/") // 41 59 2f

	assert.True(t, HasPrefixBits([]byte("AY/"), 8)([]byte{0x41, 0x59, 0x2f}))
	assert.True(t, HasPrefixBits([]byte("AY/"), 7)([]byte{0x40, 0x59, 0x2f}))

	buf := make([]byte, 32)
	rand.Read(buf)
	input := bytes.Clone(buf)

	for i := 1; i < 256; i++ {
		assert.True(t, HasPrefixBits(buf, i)(input))
	}

	input[0] ^= 0x01
	for i := 1; i < 8; i++ {
		assert.True(t, HasPrefixBits(buf, i)(input))
	}
	for i := 8; i < 256; i++ {
		assert.False(t, HasPrefixBits(buf, i)(input))
	}
}

// decodeBase64PrefixBits returns base64-decoded prefix and number of decoded bits.
func decodeBase64PrefixBits(prefix string) ([]byte, int) {
	decodedBits := 6 * len(prefix)
	quantums := (len(prefix) + 3) / 4
	prefix += strings.Repeat("A", quantums*4-len(prefix))
	buf := make([]byte, quantums*3)
	_, err := base64.StdEncoding.Decode(buf, []byte(prefix))
	if err != nil {
		panic(err)
	}
	return buf, decodedBits
}

func randUint64() uint64 {
	var num uint64
	err := binary.Read(rand.Reader, binary.NativeEndian, &num)
	if err != nil {
		panic(err)
	}
	return num
}

func scalarFromUint64(n uint64) *edwards25519.Scalar {
	var buf [64]byte
	binary.LittleEndian.PutUint64(buf[:], n)

	xs, err := edwards25519.NewScalar().SetUniformBytes(buf[:])
	if err != nil {
		panic(err)
	}
	return xs
}
