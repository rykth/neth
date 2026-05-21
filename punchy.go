package neth

import (
	"net"

	"github.com/rykth/neth/udp"
)

// Punchy implements UDP hole-punching for NAT traversal
//
// When punch is true, neth proactively sends empty UDP datagrams to peer
// addresses to open outbound NAT mappings before the handshake begins.
// When respond is true, neth automatically replies to any unrecognised
// incoming UDP datagram - keeping the NAT mapping alive on the remote side.
type Punchy struct {
	punch   bool
	respond bool
	udp     *udp.Conn
}

// NewPunchy creates a Punchy
func NewPunchy(punch, respond bool, conn *udp.Conn) *Punchy {
	return &Punchy{punch: punch, respond: respond, udp: conn}
}

// Punch sends a zero-length UDP datagram to each address in remotes.
// The empty payload opens an outbound NAT mapping without triggering any
// application-level processing on the remote peer.
func (p *Punchy) Punch(remotes []net.UDPAddr) {
	if !p.punch {
		return
	}
	for i := range remotes {
		_, _ = p.udp.WriteTo(nil, &remotes[i])
	}
}

// RespondToPunch sends a single zero-length UDP datagram back to from.
func (p *Punchy) RespondToPunch(from *net.UDPAddr) {
	if !p.respond {
		return
	}
	_, _ = p.udp.WriteTo(nil, from)
}
