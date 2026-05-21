package firewall

import (
	"net/netip"
	"sync"
	"time"
)

// connKey identifies one direction of a tracked connection.
// SrcIP/SrcPort are the sender; DstIP/DstPort are the receiver.
// When a source port is not available (e.g. from the firewall API that only
// knows the destination port), SrcPort is set to 0.
type connKey struct {
	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16
	Proto   Proto
}

func (k connKey) reversed() connKey {
	return connKey{
		SrcIP:   k.DstIP,
		DstIP:   k.SrcIP,
		SrcPort: k.DstPort,
		DstPort: k.SrcPort,
		Proto:   k.Proto,
	}
}

// conntrack is a thread-safe state table that maps active connections to the
// time they were last seen
type conntrack struct {
	mu   sync.RWMutex
	seen map[connKey]time.Time
}

func newConntrack() *conntrack {
	return &conntrack{seen: make(map[connKey]time.Time)}
}

// Track upserts the last-seen timestamp for k.
func (ct *conntrack) Track(k connKey) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.seen[k] = time.Now()
}

// IsEstablished reports whether k or its reverse direction was previously
// tracked
func (ct *conntrack) IsEstablished(k connKey) bool {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	if _, ok := ct.seen[k]; ok {
		return true
	}
	_, ok := ct.seen[k.reversed()]
	return ok
}

// Expire removes entries that have not been seen within their protocol
// timeout
func (ct *conntrack) Expire(tcpTimeout, udpTimeout, defaultTimeout time.Duration) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	now := time.Now()
	for k, last := range ct.seen {
		var ttl time.Duration
		switch k.Proto {
		case ProtoTCP:
			ttl = tcpTimeout
		case ProtoUDP:
			ttl = udpTimeout
		default:
			ttl = defaultTimeout
		}
		if now.Sub(last) >= ttl {
			delete(ct.seen, k)
		}
	}
}
