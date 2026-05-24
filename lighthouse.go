package neth

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/rykth/neth/header"
	"github.com/rykth/neth/nethpb"
)

// LightHouse maintains the registry of peer physical addresses and orchestrates
// peer-discovery and NAT-traversal signalling with designated lighthouse nodes
type LightHouse struct {
	mu           sync.RWMutex
	addrStore    map[netip.Addr][]net.UDPAddr // VPN IP → known physical addresses
	lighthouses  []netip.Addr                 // VPN IPs of designated lighthouse nodes
	amLighthouse bool
	myAddrs      []net.UDPAddr // local/external addresses to advertise

	punchy *Punchy // nil if punchy is disabled
}

// NewLightHouse creates a LightHouse.
// lighthouses is the list of lighthouse VPN IPs
// myAddrs is the list of physical addresses this node advertises
func NewLightHouse(amLighthouse bool, lighthouses []netip.Addr, myAddrs []net.UDPAddr) *LightHouse {
	return &LightHouse{
		addrStore:    make(map[netip.Addr][]net.UDPAddr),
		lighthouses:  lighthouses,
		amLighthouse: amLighthouse,
		myAddrs:      myAddrs,
	}
}

// SetPunchy wires in a Punchy instance used to send hole-punch packets when a
// HostPunchNotification arrives.
func (lh *LightHouse) SetPunchy(p *Punchy) {
	lh.punchy = p
}

// AddStaticEntry pre-populates the addr store with a known physical address
func (lh *LightHouse) AddStaticEntry(vpnIP netip.Addr, addr net.UDPAddr) {
	lh.mu.Lock()
	defer lh.mu.Unlock()
	lh.addrStore[vpnIP] = append(lh.addrStore[vpnIP], addr)
}

// GetAddrs returns the known physical addresses for vpnIP, or nil
func (lh *LightHouse) GetAddrs(vpnIP netip.Addr) []net.UDPAddr {
	lh.mu.RLock()
	defer lh.mu.RUnlock()
	if addrs, ok := lh.addrStore[vpnIP]; ok {
		out := make([]net.UDPAddr, len(addrs))
		copy(out, addrs)
		return out
	}
	return nil
}

// VpnIPByAddr performs a reverse lookup
func (lh *LightHouse) VpnIPByAddr(addr net.UDPAddr) (netip.Addr, bool) {
	lh.mu.RLock()
	defer lh.mu.RUnlock()
	for vpnIP, addrs := range lh.addrStore {
		for _, a := range addrs {
			if a.IP.Equal(addr.IP) && a.Port == addr.Port {
				return vpnIP, true
			}
		}
	}
	return netip.Addr{}, false
}

// HandleMessage dispatches an inbound LightHouseMessage
func (lh *LightHouse) HandleMessage(
	msg *nethpb.LightHouseMessage,
	from netip.Addr,
	sendFn func([]byte, *net.UDPAddr),
) {
	switch {
	case msg.GetQuery() != nil:
		lh.handleQuery(msg.GetQuery(), from, sendFn)
	case msg.GetQueryReply() != nil:
		lh.handleQueryReply(msg.GetQueryReply())
	case msg.GetUpdate() != nil:
		lh.handleUpdate(msg.GetUpdate(), from)
	case msg.GetWhoAmI() != nil:
		lh.handleWhoAmI(from, sendFn)
	case msg.GetWhoAmIReply() != nil:
		lh.handleWhoAmIReply(msg.GetWhoAmIReply())
	case msg.GetPunch() != nil:
		lh.handlePunch(msg.GetPunch())
	}
}

// handleQuery answers a HostQuery with stored addresses for the queried peer
func (lh *LightHouse) handleQuery(
	q *nethpb.HostQuery,
	replyTo netip.Addr,
	sendFn func([]byte, *net.UDPAddr),
) {
	queried, err := netip.ParseAddr(q.GetVpnIp())
	if err != nil {
		return
	}

	lh.mu.RLock()
	stored := lh.addrStore[queried]
	addrs := make([]net.UDPAddr, len(stored))
	copy(addrs, stored)
	lh.mu.RUnlock()

	reply := &nethpb.LightHouseMessage{
		Body: &nethpb.LightHouseMessage_QueryReply{
			QueryReply: &nethpb.HostQueryReply{
				VpnIp: q.GetVpnIp(),
				Addrs: udpAddrsToIpPorts(addrs),
			},
		},
	}
	lh.send(reply, replyTo, sendFn)
}

func (lh *LightHouse) handleQueryReply(r *nethpb.HostQueryReply) {
	vpnIP, err := netip.ParseAddr(r.GetVpnIp())
	if err != nil {
		return
	}
	addrs := ipPortsToUDPAddrs(r.GetAddrs())

	lh.mu.Lock()
	lh.addrStore[vpnIP] = addrs
	lh.mu.Unlock()
}

func (lh *LightHouse) handleUpdate(u *nethpb.HostUpdateNotification, from netip.Addr) {
	if !lh.amLighthouse {
		return
	}

	addrs := ipPortsToUDPAddrs(u.GetAddrs())
	lh.mu.Lock()
	lh.addrStore[from] = addrs
	lh.mu.Unlock()
}

func (lh *LightHouse) handleWhoAmI(from netip.Addr, sendFn func([]byte, *net.UDPAddr)) {
	lh.mu.RLock()
	addrs := lh.addrStore[from]
	lh.mu.RUnlock()

	var ipPort *nethpb.IpPort
	if len(addrs) > 0 {
		ipPort = udpAddrToIpPort(&addrs[0])
	}
	reply := &nethpb.LightHouseMessage{
		Body: &nethpb.LightHouseMessage_WhoAmIReply{
			WhoAmIReply: &nethpb.WhoAmIReply{Addr: ipPort},
		},
	}
	lh.send(reply, from, sendFn)
}

func (lh *LightHouse) handleWhoAmIReply(r *nethpb.WhoAmIReply) {
	if r.GetAddr() == nil {
		return
	}
	addr, err := ipPortToUDPAddr(r.GetAddr())
	if err != nil {
		return
	}
	lh.mu.Lock()
	lh.myAddrs = append([]net.UDPAddr{addr}, lh.myAddrs...)
	lh.mu.Unlock()
}

func (lh *LightHouse) handlePunch(p *nethpb.HostPunchNotification) {
	if lh.punchy == nil {
		return
	}
	lh.punchy.Punch(ipPortsToUDPAddrs(p.GetAddrs()))
}

func (lh *LightHouse) QueryPeer(vpnIP netip.Addr, sendFn func([]byte, *net.UDPAddr)) {
	msg := &nethpb.LightHouseMessage{
		Body: &nethpb.LightHouseMessage_Query{
			Query: &nethpb.HostQuery{VpnIp: vpnIP.String()},
		},
	}
	for _, lhIP := range lh.lighthouses {
		lh.send(msg, lhIP, sendFn)
	}
}

func (lh *LightHouse) Advertise(sendFn func([]byte, *net.UDPAddr)) {
	lh.mu.RLock()
	myAddrs := make([]net.UDPAddr, len(lh.myAddrs))
	copy(myAddrs, lh.myAddrs)
	lh.mu.RUnlock()

	msg := &nethpb.LightHouseMessage{
		Body: &nethpb.LightHouseMessage_Update{
			Update: &nethpb.HostUpdateNotification{
				Addrs: udpAddrsToIpPorts(myAddrs),
			},
		},
	}
	for _, lhIP := range lh.lighthouses {
		lh.send(msg, lhIP, sendFn)
	}
}

func (lh *LightHouse) Run(ctx context.Context, interval time.Duration, sendFn func([]byte, *net.UDPAddr)) {
	lh.Advertise(sendFn)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lh.Advertise(sendFn)
		}
	}
}

func (lh *LightHouse) send(
	msg *nethpb.LightHouseMessage,
	toVpnIP netip.Addr,
	sendFn func([]byte, *net.UDPAddr),
) {
	lh.mu.RLock()
	stored := lh.addrStore[toVpnIP]
	physAddrs := make([]net.UDPAddr, len(stored))
	copy(physAddrs, stored)
	lh.mu.RUnlock()

	wire, err := marshalLightHousePacket(msg)
	if err != nil {
		return
	}
	for i := range physAddrs {
		sendFn(wire, &physAddrs[i])
	}
}

func marshalLightHousePacket(msg *nethpb.LightHouseMessage) ([]byte, error) {
	body, err := proto.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("lighthouse: marshal: %w", err)
	}
	hdr := header.Header{Version: header.Version, Type: header.TypeLightHouse}
	hdrBytes := hdr.Bytes()
	pkt := make([]byte, len(hdrBytes)+len(body))
	copy(pkt, hdrBytes[:])
	copy(pkt[len(hdrBytes):], body)
	return pkt, nil
}

func ipPortToUDPAddr(p *nethpb.IpPort) (net.UDPAddr, error) {
	ip := net.ParseIP(p.GetIp())
	if ip == nil {
		return net.UDPAddr{}, fmt.Errorf("lighthouse: invalid IP %q", p.GetIp())
	}
	return net.UDPAddr{IP: ip, Port: int(p.GetPort())}, nil
}

func udpAddrToIpPort(a *net.UDPAddr) *nethpb.IpPort {
	return &nethpb.IpPort{Ip: a.IP.String(), Port: uint32(a.Port)} //nolint:gosec
}

func ipPortsToUDPAddrs(ports []*nethpb.IpPort) []net.UDPAddr {
	out := make([]net.UDPAddr, 0, len(ports))
	for _, p := range ports {
		if a, err := ipPortToUDPAddr(p); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func udpAddrsToIpPorts(addrs []net.UDPAddr) []*nethpb.IpPort {
	out := make([]*nethpb.IpPort, len(addrs))
	for i := range addrs {
		out[i] = udpAddrToIpPort(&addrs[i])
	}
	return out
}
