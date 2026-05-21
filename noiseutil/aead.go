package noiseutil

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/flynn/noise"
)

// CipherFromState extracts the 32-byte AES-256 key from a completed Noise
// CipherState and returns a cipher.AEAD backed by AES-256-GCM.
//
// The returned AEAD expects 12-byte nonces. Callers should derive nonces from
// the packet counter using CounterNonce.
func CipherFromState(cs *noise.CipherState) (cipher.AEAD, error) {
	key := cs.UnsafeKey()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("noiseutil: AES key: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("noiseutil: GCM: %w", err)
	}
	return gcm, nil
}

// Encrypt seals plaintext using aead.
//
// counter is the 64-bit monotonic packet counter taken from HostInfo.
// header is used as AEAD additional data (authenticated but not encrypted) —
// neth passes the 16-byte wire header so the counter in the header is
// cryptographically bound to the ciphertext.
func Encrypt(aead cipher.AEAD, counter uint64, header, plaintext []byte) ([]byte, error) {
	nonce := CounterNonce(counter)
	return aead.Seal(nil, nonce[:], plaintext, header), nil
}

// Decrypt opens ciphertext using aead.
//
// counter must match the counter embedded in the neth wire header; it is used
// as the AEAD nonce.  header is used as additional data (the same 16-byte wire
// header that was supplied to Encrypt).
//
// Returns an error if the AEAD tag does not verify.  Replay detection must be
// performed by the caller before this function is invoked.
func Decrypt(aead cipher.AEAD, counter uint64, header, ciphertext []byte) ([]byte, error) {
	nonce := CounterNonce(counter)
	pt, err := aead.Open(nil, nonce[:], ciphertext, header)
	if err != nil {
		return nil, fmt.Errorf("noiseutil: decrypt: %w", err)
	}
	return pt, nil
}

// CounterNonce converts a 64-bit packet counter to the 12-byte GCM nonce.
//
// Layout: [0..7] counter in little-endian, [8..11] zero.
//
// Little-endian keeps the most-significant byte at position 7 so the nonce
// space grows toward byte 7 rather than byte 0, matching the standard
// WireGuard nonce derivation and keeping compatibility notes simple.
func CounterNonce(counter uint64) [12]byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[:8], counter)
	return nonce
}
