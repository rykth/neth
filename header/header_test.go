package header_test

import (
	"math"
	"testing"

	"github.com/rykth/neth/header"
)

// roundTrip encodes h then parses the bytes, returning the decoded header
func roundTrip(t *testing.T, h *header.Header) *header.Header {
	t.Helper()
	var buf [header.HeaderLen]byte
	if err := h.Encode(buf[:]); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := header.Parse(buf[:])
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return got
}

func TestRoundTrip_AllMessageTypes(t *testing.T) {
	types := []struct {
		name    string
		typ     header.MessageType
		subType uint8
	}{
		{"Handshake/Initiation", header.TypeHandshake, uint8(header.HandshakeInitiation)},
		{"Handshake/Response", header.TypeHandshake, uint8(header.HandshakeResponse)},
		{"Message", header.TypeMessage, 0},
		{"LightHouse", header.TypeLightHouse, 0},
		{"Test", header.TypeTest, 0},
		{"CloseTunnel", header.TypeCloseTunnel, 0},
	}

	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			orig := &header.Header{
				Version:        header.Version,
				Type:           tc.typ,
				SubType:        tc.subType,
				RemoteIndex:    0xDEADBEEF,
				MessageCounter: 0xCAFEBABEDEADF00D,
			}
			got := roundTrip(t, orig)

			if got.Version != orig.Version {
				t.Errorf("Version: got %d, want %d", got.Version, orig.Version)
			}
			if got.Type != orig.Type {
				t.Errorf("Type: got %v, want %v", got.Type, orig.Type)
			}
			if got.SubType != orig.SubType {
				t.Errorf("SubType: got %d, want %d", got.SubType, orig.SubType)
			}
			if got.RemoteIndex != orig.RemoteIndex {
				t.Errorf("RemoteIndex: got %#x, want %#x", got.RemoteIndex, orig.RemoteIndex)
			}
			if got.MessageCounter != orig.MessageCounter {
				t.Errorf("MessageCounter: got %#x, want %#x", got.MessageCounter, orig.MessageCounter)
			}
		})
	}
}

func TestRoundTrip_BoundaryValues(t *testing.T) {
	cases := []struct {
		name string
		h    header.Header
	}{
		{
			name: "all zeros",
			h:    header.Header{Version: header.Version},
		},
		{
			name: "max RemoteIndex",
			h:    header.Header{Version: header.Version, Type: header.TypeMessage, RemoteIndex: math.MaxUint32},
		},
		{
			name: "max MessageCounter",
			h:    header.Header{Version: header.Version, Type: header.TypeMessage, MessageCounter: math.MaxUint64},
		},
		{
			name: "max RemoteIndex and MessageCounter",
			h: header.Header{
				Version:        header.Version,
				Type:           header.TypeMessage,
				SubType:        0xFF,
				RemoteIndex:    math.MaxUint32,
				MessageCounter: math.MaxUint64,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := roundTrip(t, &tc.h)
			if got.RemoteIndex != tc.h.RemoteIndex {
				t.Errorf("RemoteIndex: got %#x, want %#x", got.RemoteIndex, tc.h.RemoteIndex)
			}
			if got.MessageCounter != tc.h.MessageCounter {
				t.Errorf("MessageCounter: got %#x, want %#x", got.MessageCounter, tc.h.MessageCounter)
			}
			if got.SubType != tc.h.SubType {
				t.Errorf("SubType: got %d, want %d", got.SubType, tc.h.SubType)
			}
		})
	}
}

func TestParse_TruncatedBuffer(t *testing.T) {
	sizes := []int{0, 1, 7, 8, 15}
	for _, size := range sizes {
		buf := make([]byte, size)
		if _, err := header.Parse(buf); err == nil {
			t.Errorf("Parse(%d-byte buffer): expected error, got nil", size)
		}
	}
}

func TestEncode_TruncatedBuffer(t *testing.T) {
	h := &header.Header{Version: header.Version, Type: header.TypeMessage}
	sizes := []int{0, 1, 7, 8, 15}
	for _, size := range sizes {
		buf := make([]byte, size)
		if err := h.Encode(buf); err == nil {
			t.Errorf("Encode(%d-byte buffer): expected error, got nil", size)
		}
	}
}

func TestParse_WrongVersion(t *testing.T) {
	h := &header.Header{Version: header.Version, Type: header.TypeMessage}
	var buf [header.HeaderLen]byte
	_ = h.Encode(buf[:])

	// corrupt the version nibble - set it to 2
	buf[0] = (2 << 4) | (buf[0] & 0x0F)

	if _, err := header.Parse(buf[:]); err == nil {
		t.Error("Parse with wrong version: expected error, got nil")
	}
}

func TestParse_ExactSize(t *testing.T) {
	h := &header.Header{
		Version:        header.Version,
		Type:           header.TypeLightHouse,
		RemoteIndex:    42,
		MessageCounter: 1000,
	}
	buf := h.Bytes()
	got, err := header.Parse(buf[:])
	if err != nil {
		t.Fatalf("Parse exact-size buffer: %v", err)
	}
	if got.RemoteIndex != 42 {
		t.Errorf("RemoteIndex: got %d, want 42", got.RemoteIndex)
	}
	if got.MessageCounter != 1000 {
		t.Errorf("MessageCounter: got %d, want 1000", got.MessageCounter)
	}
}

func TestParse_LargerBuffer(t *testing.T) {
	h := &header.Header{
		Version:        header.Version,
		Type:           header.TypeMessage,
		RemoteIndex:    7,
		MessageCounter: 99,
	}
	buf := make([]byte, header.HeaderLen+128)
	_ = h.Encode(buf)
	// fill the trailing bytes with garbage
	for i := header.HeaderLen; i < len(buf); i++ {
		buf[i] = 0xFF
	}

	got, err := header.Parse(buf)
	if err != nil {
		t.Fatalf("Parse larger buffer: %v", err)
	}
	if got.RemoteIndex != 7 || got.MessageCounter != 99 {
		t.Errorf("unexpected values after parse: %+v", got)
	}
}

func TestReservedBytesAreZero(t *testing.T) {
	h := &header.Header{Version: header.Version, Type: header.TypeMessage}
	buf := h.Bytes()
	// bytes 2 and 3 are reserved and must always be zero on write
	if buf[2] != 0 || buf[3] != 0 {
		t.Errorf("reserved bytes non-zero: buf[2]=%#x buf[3]=%#x", buf[2], buf[3])
	}
}

func TestMessageTypeString(t *testing.T) {
	cases := []struct {
		typ  header.MessageType
		want string
	}{
		{header.TypeHandshake, "Handshake"},
		{header.TypeMessage, "Message"},
		{header.TypeLightHouse, "LightHouse"},
		{header.TypeTest, "Test"},
		{header.TypeCloseTunnel, "CloseTunnel"},
		{header.MessageType(0xFF), "Unknown(255)"},
	}
	for _, tc := range cases {
		if got := tc.typ.String(); got != tc.want {
			t.Errorf("MessageType(%d).String() = %q, want %q", tc.typ, got, tc.want)
		}
	}
}

func TestBytes_Idempotent(t *testing.T) {
	h := &header.Header{
		Version:        header.Version,
		Type:           header.TypeHandshake,
		SubType:        uint8(header.HandshakeInitiation),
		RemoteIndex:    0x12345678,
		MessageCounter: 0xABCDEF0123456789,
	}
	b1 := h.Bytes()
	b2 := h.Bytes()
	if b1 != b2 {
		t.Error("Bytes() is not idempotent")
	}
}
