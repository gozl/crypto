package crypto

import (
	"crypto/rand"
	"io"
)

// GetBytes returns a slice of bytes from crypto/rand Reader. Returns nil if 
// reading from rand.Reader fails.
func GetBytes(length int) []byte {
	k := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil
	}

	return k
}
