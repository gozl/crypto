package crypto

import (
	"crypto/sha256"
	"crypto/cipher"
	"crypto/aes"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base64"
	"hash"
	"fmt"
	"errors"
	"time"
	"bytes"
	"strconv"
)

// HMACEncoder is an encoder that can verify and optionally encrypt message
type HMACEncoder struct {
	hashKey  []byte
	blockKey []byte
	hashFunc func() hash.Hash
	block    cipher.Block
}

// NewHMACEncoder returns a new instance of the HMACEncoder. Hash key must be 32 or 64 bytes. Block key can be nil, which 
// will disable encryption, or 16|24|32 bytes (AES-128|192|256).
func NewHMACEncoder(hashKey, blockKey []byte) (*HMACEncoder, error) {
	if hashKey == nil || len(hashKey) == 0 {
		return nil, errors.New("hash key must be specified")
	}
	if (len(hashKey) != 32 && len(hashKey) != 64) {
		return nil, errors.New("hash key must be 32 or 64 bytes")
	}

	s := &HMACEncoder{
		hashKey:  hashKey,
		blockKey: blockKey,
		hashFunc: sha256.New,
	}

	if blockKey != nil {
		size := len(blockKey)
		if size != 16 && size != 24 && size != 32 {
			return nil, errors.New("block key must be 16, 24 or 32 bytes")
		}

		s.blockFunc(aes.NewCipher)
	}

	return s, nil
}

// Encode produces a base64 encoded value that is HMAC signed. It will also be encrypted if 
// the HMACEncoder is initialized with blockKeys.
func (s *HMACEncoder) Encode(name string, data []byte) ([]byte, error) {
	if s.hashKey == nil {
		return nil, errors.New("hash key missing")
	}

	var encoded []byte

	// encrypt
	if s.block != nil {
		iv := GetBytes(s.block.BlockSize())
		if iv == nil {
			return nil, errors.New("unable to read from randomizer source")
		}
		stream := cipher.NewCTR(s.block, iv)
		stream.XORKeyStream(data, data)
		encrypted := append(iv, data...)
		// encode to base64 (url safe)
		encoded = encodeBase64(encrypted)
	} else {
		encoded = encodeBase64(data)
	}

	b := []byte(fmt.Sprintf("%s|%d|%s|", name, time.Now().UTC().Unix(), encoded))
	hasher := hmac.New(s.hashFunc, s.hashKey)
	hasher.Write(b[:len(b)-1])
	mac := hasher.Sum(nil)

	// pop name and push mac
	b = append(b, mac...)[len(name)+1:]
	return encodeBase64(b), nil
}

// Decode restores the data processed by Encode().
func (s *HMACEncoder) Decode(name string, data []byte, dst *[]byte) error {
	return s.DecodeWithTTL(name, 0, 0, data, dst)
}

// DecodeWithTTL restores the data processed by Encode(). An error occurs if minAge or maxAge 
// TTL (seconds) check fails with the embedded message timestamp.
func (s *HMACEncoder) DecodeWithTTL(name string, minAge, maxAge int64, data []byte, dst *[]byte) error {
	if s.hashKey == nil {
		return errors.New("hash key missing")
	}

	decoded, err := decodeBase64(data)
	if err != nil {
		return err
	}

	// date|value|mac
	macParts := bytes.SplitN(decoded, []byte("|"), 3)
	if len(macParts) != 3 {
		return errors.New("invalid mac format")
	}

	hasher := hmac.New(s.hashFunc, s.hashKey)
	b := append([]byte(name + "|"), decoded[:len(decoded)-len(macParts[2])-1]...)

	// verify mac
	hasher.Write(b)
	mac2 := hasher.Sum(nil)
	if len(macParts[2]) != len(mac2) || subtle.ConstantTimeCompare(macParts[2], mac2) != 1 {
		return errors.New("mac verification mismatch")
	}

	// verify timestamp
	var t1 int64
	if t1, err = strconv.ParseInt(string(macParts[0]), 10, 64); err != nil {
		return errors.New("invalid timestamp")
	}
	t2 := time.Now().UTC().Unix()
	if (minAge > 0) && (t1 > (t2-minAge)) {
		return errors.New("data not valid yet")
	}
	if (maxAge > 0) && (t1 < (t2-maxAge)) {
		return errors.New("data has expired")
	}

	b, err = decodeBase64(macParts[1])
	if err != nil {
		return err
	}

	// encryption
	if s.block != nil {
		size := s.block.BlockSize()
		if len(b) <= size {
			return errors.New("decryption failed")
		}

		iv := b[:size]
		b = b[size:]
		stream := cipher.NewCTR(s.block, iv)
		stream.XORKeyStream(b, b)
	}

	// set value and return
	*dst = b
	return nil
}

func encodeBase64(data []byte) []byte {
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(data)))
	base64.URLEncoding.Encode(encoded, data)

	return encoded
}

func decodeBase64(data []byte) ([]byte, error) {
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(data)))
	b, err := base64.URLEncoding.Decode(decoded, data)
	if err != nil {
		return nil, err
	}

	return decoded[:b], nil
}

func (s *HMACEncoder) blockFunc(f func([]byte) (cipher.Block, error)) error {
	block, err := f(s.blockKey)

	if err == nil {
		s.block = block
	}

	return err
}
