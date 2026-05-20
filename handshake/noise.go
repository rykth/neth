package handshake

import (
	"fmt"

	"github.com/flynn/noise"
)

// cipherSuite is Noise_*_25519_AESGCM_SHA256
var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)

// NewInitiatorState creates a Noise IKpsk0 HandshakeState for the party
// that initiates the connection.
func NewInitiatorState(localStatic noise.DHKey, remoteStatic, psk []byte) (*noise.HandshakeState, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           cipherSuite,
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		StaticKeypair:         localStatic,
		PeerStatic:            remoteStatic,
		PresharedKey:          psk,
		PresharedKeyPlacement: 0, // psk0: mix before first message
	})
	if err != nil {
		return nil, fmt.Errorf("noise: new initiator state: %w", err)
	}
	return hs, nil
}

// NewResponderState creates a Noise IKpsk0 HandshakeState for the party
// that receives the initial message.
func NewResponderState(localStatic noise.DHKey, psk []byte) (*noise.HandshakeState, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           cipherSuite,
		Pattern:               noise.HandshakeIK,
		Initiator:             false,
		StaticKeypair:         localStatic,
		PresharedKey:          psk,
		PresharedKeyPlacement: 0,
	})
	if err != nil {
		return nil, fmt.Errorf("noise: new responder state: %w", err)
	}
	return hs, nil
}
