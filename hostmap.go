package neth

import (
	"crypto/cipher"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/rykth/neth/cert"
)

// replayWindowSize is the number of counters tracked in the bitmap.
// 64 uint64s × 64 bits = 4096 individual counter slots.
const replayWindowSize = 64 * 64

// HostInfo holds all per-peer session state after a successful handshake.
type HostInfo struct {
	VpnIP       netip.Addr
	Remote      *net.UDPAddr
	Index       uint32 // local index neth assigned to this session
	RemoteIndex uint32 // index the remote peer assigned
	SendCipher  cipher.AEAD
	RecvCipher  cipher.AEAD
	Counter     atomic.Uint64
	Cert        *cert.Certificate

	// Replay detection: sliding window over the last replayWindowSize counters.
	windowEnd uint64 // highest counter accepted (non-replay)
	window    [64]uint64
	windowMu  sync.Mutex
}

// CheckReplay returns true if counter was already received (replay) or is too
// old (outside the window). If it returns false the counter is marked seen.
// Thread-safe.
func (h *HostInfo) CheckReplay(counter uint64) bool {
	h.windowMu.Lock()
	defer h.windowMu.Unlock()

	end := h.windowEnd

	if counter > end {
		diff := counter - end
		if diff >= replayWindowSize {
			// large jump(clear the entire window and start fresh)
			h.window = [64]uint64{}
		} else {
			// Shift the bitmap right by diff positions so bit 0 will
			// represent the new windowEnd (counter).
			shiftWindow(&h.window, diff)
		}
		h.windowEnd = counter
		h.window[0] |= 1 // mark bit 0 (the new counter)
		return false
	}

	if end-counter >= replayWindowSize {
		return true // too old — outside the window
	}

	pos := end - counter
	word := pos / 64
	bit := pos % 64
	if h.window[word]&(1<<bit) != 0 {
		return true // seen before
	}
	h.window[word] |= 1 << bit
	return false
}

// shiftWindow shifts the 64-uint64 bitmap right by n bit positions.
// Bits shifted beyond position [63][63] are discarded.
func shiftWindow(w *[64]uint64, n uint64) {
	wordShift := n / 64
	bitShift := n % 64

	// Shift whole words first.
	if wordShift >= 64 {
		*w = [64]uint64{}
		return
	}
	for i := 63; i >= 0; i-- {
		src := int(i) - int(wordShift)
		if src < 0 {
			w[i] = 0
		} else {
			w[i] = w[src]
		}
	}

	// Then shift within words: bit at position p moves to p+bitShift(leftshift)
	// High bits of word i-1 carry over into the low bits of word i.
	if bitShift > 0 {
		for i := 63; i > 0; i-- {
			w[i] = (w[i] << bitShift) | (w[i-1] >> (64 - bitShift))
		}
		w[0] <<= bitShift
	}
}

// HostMap is a thread-safe registry of active peer sessions, keyed by both
// VPN IP and local session index.
type HostMap struct {
	mu      sync.RWMutex
	byVpnIP map[netip.Addr]*HostInfo
	byIndex map[uint32]*HostInfo
}

// NewHostMap returns an empty HostMap.
func NewHostMap() *HostMap {
	return &HostMap{
		byVpnIP: make(map[netip.Addr]*HostInfo),
		byIndex: make(map[uint32]*HostInfo),
	}
}

// Add inserts h into both indexes.  Any previous entry with the same VPN IP
// or index is replaced.
func (m *HostMap) Add(h *HostInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byVpnIP[h.VpnIP] = h
	m.byIndex[h.Index] = h
}

// GetByVpnIP returns the HostInfo for the given VPN IP, or nil.
func (m *HostMap) GetByVpnIP(ip netip.Addr) *HostInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byVpnIP[ip]
}

// GetByIndex returns the HostInfo for the given local index, or nil.
func (m *HostMap) GetByIndex(idx uint32) *HostInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byIndex[idx]
}

// Remove deletes the HostInfo for the given VPN IP and its index entry.
func (m *HostMap) Remove(ip netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if h := m.byVpnIP[ip]; h != nil {
		delete(m.byIndex, h.Index)
	}
	delete(m.byVpnIP, ip)
}
