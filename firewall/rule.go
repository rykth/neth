package firewall

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rykth/neth/config"
)

type Proto uint8

const (
	ProtoAny  Proto = 0  // wildcard — matches any protocol
	ProtoICMP Proto = 1  // IANA 1
	ProtoTCP  Proto = 6  // IANA 6
	ProtoUDP  Proto = 17 // IANA 17
)

func (p Proto) String() string {
	switch p {
	case ProtoAny:
		return "any"
	case ProtoICMP:
		return "icmp"
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	default:
		return strconv.Itoa(int(p))
	}
}

// Rule is a compiled firewall rule. Fields ending in "Any" are wildcard
// flags; when set, the corresponding value field is ignored.
type Rule struct {
	Port     uint16
	PortAny  bool
	Proto    Proto
	Group    string
	GroupAny bool
	CIDR     netip.Prefix
	CIDAny   bool
}

// ParseRule converts a config.FirewallRule into a typed Rule
func ParseRule(r config.FirewallRule) (Rule, error) {
	var rule Rule

	switch strings.ToLower(strings.TrimSpace(r.Proto)) {
	case "", "any":
		rule.Proto = ProtoAny
	case "tcp":
		rule.Proto = ProtoTCP
	case "udp":
		rule.Proto = ProtoUDP
	case "icmp":
		rule.Proto = ProtoICMP
	default:
		return Rule{}, fmt.Errorf("firewall: unknown protocol %q", r.Proto)
	}

	switch strings.ToLower(strings.TrimSpace(r.Port)) {
	case "", "any":
		rule.PortAny = true
	default:
		p, err := strconv.ParseUint(r.Port, 10, 16)
		if err != nil {
			return Rule{}, fmt.Errorf("firewall: invalid port %q: %w", r.Port, err)
		}
		rule.Port = uint16(p)
	}

	switch strings.TrimSpace(r.Group) {
	case "", "any":
		rule.GroupAny = true
	default:
		rule.Group = r.Group
	}

	switch strings.ToLower(strings.TrimSpace(r.CIDR)) {
	case "", "any":
		rule.CIDAny = true
	default:
		prefix, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			return Rule{}, fmt.Errorf("firewall: invalid CIDR %q: %w", r.CIDR, err)
		}
		rule.CIDR = prefix.Masked() // normalise host bits
	}

	return rule, nil
}
