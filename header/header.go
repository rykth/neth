// Package header defines the 16-byte binary header that prefixes every neth
// packet on the wire. The layout is fixed and version-tagged so that future
// format changes can be detected cleanly.
//
// Wire layout (big-endian):
//
//	Byte  0   : Version (high 4 bits) | MessageType (low 4 bits)
//	Byte  1   : SubType
//	Bytes 2–3 : Reserved (must be zero on write, ignored on read)
//	Bytes 4–7 : RemoteIndex (uint32) - receiver's local connection index
//	Bytes 8–15: MessageCounter (uint64) - monotonic counter / AEAD nonce
package header

import (
	"encoding/binary"
	"fmt"
)

const (
	Version   = 1
	HeaderLen = 16
)

type MessageType uint8

const (
	TypeHandshake   MessageType = 0 // Noise Protocol handshake (stage 0 or 1)
	TypeMessage     MessageType = 1 // Encrypted data packet
	TypeLightHouse  MessageType = 2 // Discovery protocol (lighthouse queries/replies)
	TypeTest        MessageType = 3 // Connectivity test (ping/pong)
	TypeCloseTunnel MessageType = 4 // Graceful session teardown
)

func (t MessageType) String() string {
	switch t {
	case TypeHandshake:
		return "Handshake"
	case TypeMessage:
		return "Message"
	case TypeLightHouse:
		return "LightHouse"
	case TypeTest:
		return "Test"
	case TypeCloseTunnel:
		return "CloseTunnel"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(t))
	}
}

type HandshakeSubType uint8

const (
	HandshakeInitiation HandshakeSubType = 0 // initiator → responder (message 1)
	HandshakeResponse   HandshakeSubType = 1 // responder → initiator (message 2)
)

// Header is the decoded form of a 16-byte neth packet header.
type Header struct {
	Version        uint8
	Type           MessageType
	SubType        uint8
	RemoteIndex    uint32
	MessageCounter uint64
}

// Encode writes the header into buf.
func (h *Header) Encode(buf []byte) error {
	if len(buf) < HeaderLen {
		return fmt.Errorf("header: buffer too small: need %d bytes, got %d", HeaderLen, len(buf))
	}
	buf[0] = (h.Version << 4) | (uint8(h.Type) & 0x0F)
	buf[1] = h.SubType
	buf[2] = 0 // reserved
	buf[3] = 0 // reserved
	binary.BigEndian.PutUint32(buf[4:8], h.RemoteIndex)
	binary.BigEndian.PutUint64(buf[8:16], h.MessageCounter)
	return nil
}

// Parse decodes a header from buf.
func Parse(buf []byte) (*Header, error) {
	if len(buf) < HeaderLen {
		return nil, fmt.Errorf("header: too short: need %d bytes, got %d", HeaderLen, len(buf))
	}
	v := buf[0] >> 4
	if v != Version {
		return nil, fmt.Errorf("header: unsupported version %d (want %d)", v, Version)
	}
	return &Header{
		Version:        v,
		Type:           MessageType(buf[0] & 0x0F),
		SubType:        buf[1],
		RemoteIndex:    binary.BigEndian.Uint32(buf[4:8]),
		MessageCounter: binary.BigEndian.Uint64(buf[8:16]),
	}, nil
}

func (h *Header) Bytes() [HeaderLen]byte {
	var buf [HeaderLen]byte
	_ = h.Encode(buf[:]) // cannot fail: buffer is exactly HeaderLen
	return buf
}
