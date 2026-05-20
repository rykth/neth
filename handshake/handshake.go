package handshake

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/rykth/neth/cert"
	"github.com/rykth/neth/nethpb"
)

// DerivePreSharedKey returns a 32-byte PSK from two peer certificates.
func DerivePreSharedKey(local, remote *cert.Certificate) []byte {
	lf := local.Fingerprint()
	rf := remote.Fingerprint()
	psk := make([]byte, sha256.Size)
	for i := range psk {
		psk[i] = lf[i] ^ rf[i]
	}
	return psk
}

// BuildInitiatorMessage constructs the first-stage HandshakeMessage.
func BuildInitiatorMessage(localCert *cert.Certificate, noisePayload []byte, localIndex uint32) (*nethpb.HandshakeMessage, error) {
	details := &nethpb.HandshakeDetails{
		Cert:           localCert.PEM(),
		InitiatorIndex: localIndex,
		ResponderIndex: 0,
		Time:           uint64(time.Now().UnixNano()),
	}
	detailsBytes, err := proto.Marshal(details)
	if err != nil {
		return nil, fmt.Errorf("handshake: marshal details: %w", err)
	}

	mac := hmac.New(sha256.New, localCert.Fingerprint())
	mac.Write(detailsBytes)
	mac.Write(noisePayload)

	return &nethpb.HandshakeMessage{
		Details:      detailsBytes,
		NoisePayload: noisePayload,
		Hmac:         mac.Sum(nil),
	}, nil
}

// BuildResponderMessage constructs the second-stage HandshakeMessage.
func BuildResponderMessage(localCert *cert.Certificate, noisePayload []byte, initiatorIndex, responderIndex uint32) (*nethpb.HandshakeMessage, error) {
	details := &nethpb.HandshakeDetails{
		Cert:           localCert.PEM(),
		InitiatorIndex: initiatorIndex,
		ResponderIndex: responderIndex,
		Time:           uint64(time.Now().UnixNano()),
	}
	detailsBytes, err := proto.Marshal(details)
	if err != nil {
		return nil, fmt.Errorf("handshake: marshal responder details: %w", err)
	}

	mac := hmac.New(sha256.New, localCert.Fingerprint())
	mac.Write(detailsBytes)
	mac.Write(noisePayload)

	return &nethpb.HandshakeMessage{
		Details:      detailsBytes,
		NoisePayload: noisePayload,
		Hmac:         mac.Sum(nil),
	}, nil
}

// ParseHandshakeMessage deserialises a HandshakeMessage from raw wire bytes.
func ParseHandshakeMessage(raw []byte) (*nethpb.HandshakeMessage, error) {
	msg := new(nethpb.HandshakeMessage)
	if err := proto.Unmarshal(raw, msg); err != nil {
		return nil, fmt.Errorf("handshake: parse message: %w", err)
	}
	return msg, nil
}

// ParseDetails deserialises the HandshakeDetails bytes embedded in a message.
func ParseDetails(msg *nethpb.HandshakeMessage) (*nethpb.HandshakeDetails, error) {
	d := new(nethpb.HandshakeDetails)
	if err := proto.Unmarshal(msg.Details, d); err != nil {
		return nil, fmt.Errorf("handshake: parse details: %w", err)
	}
	return d, nil
}

// VerifyHMAC authenticates a HandshakeMessage against the sender's certificate.
func VerifyHMAC(msg *nethpb.HandshakeMessage, senderCert *cert.Certificate) error {
	mac := hmac.New(sha256.New, senderCert.Fingerprint())
	mac.Write(msg.Details)
	mac.Write(msg.NoisePayload)
	if !hmac.Equal(mac.Sum(nil), msg.Hmac) {
		return errors.New("handshake: HMAC verification failed")
	}
	return nil
}
