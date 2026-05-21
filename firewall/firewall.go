package firewall

import (
	"net/netip"
)

// Firewall holds compiled inbound and outbound rule sets and a shared
// connection-tracking table.
type Firewall struct {
	inbound  []Rule
	outbound []Rule
	ct       *conntrack
}

// New returns a Firewall with the given inbound and outbound rule slices.
func New(inbound, outbound []Rule) *Firewall {
	return &Firewall{
		inbound:  inbound,
		outbound: outbound,
		ct:       newConntrack(),
	}
}

// AllowInbound returns true if an inbound packet from srcIP (member of
// srcGroups) to local dstPort with the given proto should be accepted.
func (f *Firewall) AllowInbound(srcIP netip.Addr, srcGroups []string, dstPort uint16, proto Proto) bool {
	k := connKey{DstIP: srcIP, DstPort: dstPort, Proto: proto}
	if f.ct.IsEstablished(k) {
		return true
	}

	for _, r := range f.inbound {
		if matches(r, srcIP, srcGroups, dstPort, proto) {
			f.ct.Track(k)
			return true
		}
	}

	return false
}

// AllowOutbound returns true if an outbound packet to dstIP (member of
// dstGroups) on dstPort with the given proto should be accepted.
func (f *Firewall) AllowOutbound(dstIP netip.Addr, dstGroups []string, dstPort uint16, proto Proto) bool {
	k := connKey{DstIP: dstIP, DstPort: dstPort, Proto: proto}
	if f.ct.IsEstablished(k) {
		return true
	}

	for _, r := range f.outbound {
		if matches(r, dstIP, dstGroups, dstPort, proto) {
			f.ct.Track(k)
			return true
		}
	}

	return false
}

func matches(r Rule, remoteIP netip.Addr, remoteGroups []string, port uint16, proto Proto) bool {
	if r.Proto != ProtoAny && r.Proto != proto {
		return false
	}

	if !r.PortAny && r.Port != port {
		return false
	}

	if !r.GroupAny {
		found := false
		for _, g := range remoteGroups {
			if g == r.Group {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if !r.CIDAny && !r.CIDR.Contains(remoteIP) {
		return false
	}

	return true
}
