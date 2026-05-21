package neth

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/rykth/neth/cert"
	"github.com/rykth/neth/handshake"
	"github.com/rykth/neth/header"
	"github.com/rykth/neth/nethpb"
	"github.com/rykth/neth/noiseutil"
	"github.com/rykth/neth/udp"

	noise "github.com/flynn/noise"
)

const (
	maxPendingPackets    = 50
	maxHandshakeAttempts = 10
	retryBase            = 500 * time.Millisecond
	retryMax             = 30 * time.Second
)

// pendingHandshake tracks an in-progress outbound handshake.
type pendingHandshake struct {
	state          *noise.HandshakeState
	localIndex     uint32
	remoteVpnIP    netip.Addr
	remoteAddr     *net.UDPAddr
	pendingPackets [][]byte // packets waiting for the session to establish
	attempts       int
	nextRetry      time.Time
	// stage0msg is the serialised wire packet to retransmit on timeout.
	stage0msg []byte
}

type OnComplete func(h *HostInfo, pending [][]byte)

// HandshakeManager orchestrates Noise IKpsk0 handshakes with remote peers.
// It is safe for concurrent use.
type HandshakeManager struct {
	localCert  *cert.Certificate
	localKey   noise.DHKey
	caPool     []*cert.Certificate
	conn       *udp.Conn
	onComplete OnComplete

	mu       sync.Mutex
	pending  map[netip.Addr]*pendingHandshake // keyed by remote VPN IP
	indexMap map[uint32]*pendingHandshake     // keyed by local index
}

// NewHandshakeManager creates a manager.
func NewHandshakeManager(
	localCert *cert.Certificate,
	localKey noise.DHKey,
	caPool []*cert.Certificate,
	conn *udp.Conn,
	onComplete OnComplete,
) *HandshakeManager {
	return &HandshakeManager{
		localCert:  localCert,
		localKey:   localKey,
		caPool:     caPool,
		conn:       conn,
		onComplete: onComplete,
		pending:    make(map[netip.Addr]*pendingHandshake),
		indexMap:   make(map[uint32]*pendingHandshake),
	}
}

// StartHandshake initiates an outbound handshake toward remoteVpnIP at addr.
func (m *HandshakeManager) StartHandshake(remoteVpnIP netip.Addr, addr *net.UDPAddr, remoteCert *cert.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.pending[remoteVpnIP]; ok {
		return nil // already in progress
	}

	localIndex, err := randomIndex()
	if err != nil {
		return fmt.Errorf("handshake: random index: %w", err)
	}

	psk := handshake.DerivePreSharedKey(m.localCert, remoteCert)
	hs, err := handshake.NewInitiatorState(m.localKey, remoteCert.X25519PublicKey, psk)
	if err != nil {
		return fmt.Errorf("handshake: initiator state: %w", err)
	}

	// Write stage-0 Noise message (empty application payload; the cert is
	// carried in the outer HandshakeMessage.details, not in the Noise payload).
	noiseMsg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return fmt.Errorf("handshake: write stage-0: %w", err)
	}

	wireBytes, err := buildHandshakePacket(m.localCert, noiseMsg, localIndex, header.HandshakeInitiation)
	if err != nil {
		return err
	}

	ph := &pendingHandshake{
		state:       hs,
		localIndex:  localIndex,
		remoteVpnIP: remoteVpnIP,
		remoteAddr:  addr,
		attempts:    1,
		nextRetry:   time.Now().Add(retryBase),
		stage0msg:   wireBytes,
	}

	m.pending[remoteVpnIP] = ph
	m.indexMap[localIndex] = ph

	_, err = m.conn.WriteTo(wireBytes, addr)
	return err
}

// HandleStage0 processes an inbound stage-0 handshake packet
// (TypeHandshake / HandshakeInitiation).
// pkt is the full UDP payload (neth header + body).
func (m *HandshakeManager) HandleStage0(pkt []byte, from *net.UDPAddr) error {
	if len(pkt) < header.HeaderLen {
		return fmt.Errorf("handshake: stage0 packet too short: %d", len(pkt))
	}
	if _, err := header.Parse(pkt); err != nil {
		return fmt.Errorf("handshake: parse header: %w", err)
	}

	msg, err := handshake.ParseHandshakeMessage(pkt[header.HeaderLen:])
	if err != nil {
		return err
	}
	details, err := handshake.ParseDetails(msg)
	if err != nil {
		return err
	}

	// Authenticate the outer envelope before touching Noise.
	senderCert, err := cert.Parse(details.Cert)
	if err != nil {
		return fmt.Errorf("handshake: parse sender cert: %w", err)
	}
	if err := cert.Verify(senderCert, m.caPool, time.Now()); err != nil {
		return fmt.Errorf("handshake: cert verify: %w", err)
	}
	if err := handshake.VerifyHMAC(msg, senderCert); err != nil {
		return err
	}

	psk := handshake.DerivePreSharedKey(m.localCert, senderCert)
	respHS, err := handshake.NewResponderState(m.localKey, psk)
	if err != nil {
		return err
	}

	// Consume stage-0 Noise message.
	if _, _, _, err := respHS.ReadMessage(nil, msg.NoisePayload); err != nil {
		return fmt.Errorf("handshake: noise read stage-0: %w", err)
	}

	// Generate local index and write stage-1 reply.
	localIndex, err := randomIndex()
	if err != nil {
		return err
	}

	noiseReply, cs1, cs2, err := respHS.WriteMessage(nil, nil)
	if err != nil {
		return fmt.Errorf("handshake: noise write stage-1: %w", err)
	}

	respMsg, err := handshake.BuildResponderMessage(m.localCert, noiseReply, details.InitiatorIndex, localIndex)
	if err != nil {
		return err
	}
	respBytes, err := marshalHandshakePacket(respMsg, details.InitiatorIndex, header.HandshakeResponse)
	if err != nil {
		return err
	}

	if _, err := m.conn.WriteTo(respBytes, from); err != nil {
		return fmt.Errorf("handshake: send stage-1: %w", err)
	}

	// handshake complete on the responder side.
	sendCipher, recvCipher, err := ciphersFromStates(cs1, cs2, false)
	if err != nil {
		return err
	}
	host := &HostInfo{
		VpnIP:       senderCert.VpnIP.Addr(),
		Remote:      from,
		Index:       localIndex,
		RemoteIndex: details.InitiatorIndex,
		SendCipher:  sendCipher,
		RecvCipher:  recvCipher,
		Cert:        senderCert,
	}
	m.onComplete(host, nil)
	return nil
}

// HandleStage1 processes an inbound stage-1 handshake packet
// (TypeHandshake /  HandshakeResponse).
// pkt is the full UDP payload.
func (m *HandshakeManager) HandleStage1(pkt []byte) error {
	if len(pkt) < header.HeaderLen {
		return fmt.Errorf("handshake: stage1 packet too short: %d", len(pkt))
	}
	h, err := header.Parse(pkt)
	if err != nil {
		return fmt.Errorf("handshake: parse header: %w", err)
	}

	m.mu.Lock()
	ph, ok := m.indexMap[h.RemoteIndex]
	if ok {
		delete(m.pending, ph.remoteVpnIP)
		delete(m.indexMap, h.RemoteIndex)
	}
	m.mu.Unlock()

	if !ok {
		return fmt.Errorf("handshake: unknown RemoteIndex %d", h.RemoteIndex)
	}

	msg, err := handshake.ParseHandshakeMessage(pkt[header.HeaderLen:])
	if err != nil {
		return err
	}
	details, err := handshake.ParseDetails(msg)
	if err != nil {
		return err
	}

	responderCert, err := cert.Parse(details.Cert)
	if err != nil {
		return fmt.Errorf("handshake: parse responder cert: %w", err)
	}
	if err := cert.Verify(responderCert, m.caPool, time.Now()); err != nil {
		return fmt.Errorf("handshake: cert verify: %w", err)
	}
	if err := handshake.VerifyHMAC(msg, responderCert); err != nil {
		return err
	}

	_, cs1, cs2, err := ph.state.ReadMessage(nil, msg.NoisePayload)
	if err != nil {
		return fmt.Errorf("handshake: noise read stage-1: %w", err)
	}

	sendCipher, recvCipher, err := ciphersFromStates(cs1, cs2, true)
	if err != nil {
		return err
	}
	host := &HostInfo{
		VpnIP:       ph.remoteVpnIP,
		Remote:      ph.remoteAddr,
		Index:       ph.localIndex,
		RemoteIndex: details.ResponderIndex,
		SendCipher:  sendCipher,
		RecvCipher:  recvCipher,
		Cert:        responderCert,
	}
	m.onComplete(host, ph.pendingPackets)
	return nil
}

// QueuePacket stores a plaintext packet destined for remoteVpnIP while the
// handshake is pending
func (m *HandshakeManager) QueuePacket(remoteVpnIP netip.Addr, pkt []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ph, ok := m.pending[remoteVpnIP]
	if !ok {
		return
	}
	if len(ph.pendingPackets) >= maxPendingPackets {
		ph.pendingPackets = ph.pendingPackets[1:] // drop oldest
	}
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	ph.pendingPackets = append(ph.pendingPackets, cp)
}

// Run processes handshake retries until ctx is cancelled.  Call in a goroutine.
func (m *HandshakeManager) Run(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			m.retryPending(now)
		}
	}
}

func (m *HandshakeManager) retryPending(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for vpnIP, ph := range m.pending {
		if now.Before(ph.nextRetry) {
			continue
		}
		if ph.attempts >= maxHandshakeAttempts {
			slog.Warn("handshake expired", "peer", vpnIP, "attempts", ph.attempts)
			delete(m.pending, vpnIP)
			delete(m.indexMap, ph.localIndex)
			continue
		}
		ph.attempts++
		delay := retryBase * time.Duration(1<<min(ph.attempts, 6)) //nolint:gosec
		if delay > retryMax {
			delay = retryMax
		}
		ph.nextRetry = now.Add(delay)
		if _, err := m.conn.WriteTo(ph.stage0msg, ph.remoteAddr); err != nil {
			slog.Warn("handshake retry failed", "peer", vpnIP, "err", err)
		}
	}
}

func randomIndex() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func buildHandshakePacket(localCert *cert.Certificate, noiseMsg []byte, localIndex uint32, subtype header.HandshakeSubType) ([]byte, error) {
	outerMsg, err := handshake.BuildInitiatorMessage(localCert, noiseMsg, localIndex)
	if err != nil {
		return nil, err
	}
	return marshalHandshakePacket(outerMsg, 0, subtype)
}

func marshalHandshakePacket(msg *nethpb.HandshakeMessage, remoteIndex uint32, subtype header.HandshakeSubType) ([]byte, error) {
	hdr := header.Header{
		Version:        header.Version,
		Type:           header.TypeHandshake,
		SubType:        uint8(subtype),
		RemoteIndex:    remoteIndex,
		MessageCounter: 0,
	}
	hdrBytes := hdr.Bytes()

	body, err := proto.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("handshake: marshal message: %w", err)
	}

	pkt := make([]byte, len(hdrBytes)+len(body))
	copy(pkt, hdrBytes[:])
	copy(pkt[len(hdrBytes):], body)
	return pkt, nil
}

// ciphersFromStates extracts send/recv cipher.AEAD from a completed Noise split.
// isInitiator selects which cipher state is the send vs recv.
//
// Noise spec: c1 = initiator -> responder, c2 = responder -> initiator.
// Initiator:  send=cs1, recv=cs2.
// Responder:  send=cs2, recv=cs1.
func ciphersFromStates(cs1, cs2 *noise.CipherState, isInitiator bool) (send cipher.AEAD, recv cipher.AEAD, err error) {
	c1, err := noiseutil.CipherFromState(cs1)
	if err != nil {
		return nil, nil, err
	}
	c2, err := noiseutil.CipherFromState(cs2)
	if err != nil {
		return nil, nil, err
	}
	if isInitiator {
		return c1, c2, nil
	}
	return c2, c1, nil
}
