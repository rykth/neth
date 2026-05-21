package firewall_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rykth/neth/config"
	"github.com/rykth/neth/firewall"
)

func parseRule(t *testing.T, port, proto, group, cidr string) firewall.Rule {
	t.Helper()
	r, err := firewall.ParseRule(config.FirewallRule{
		Port:  port,
		Proto: proto,
		Group: group,
		CIDR:  cidr,
	})
	if err != nil {
		t.Fatalf("ParseRule(%q %q %q %q): %v", port, proto, group, cidr, err)
	}
	return r
}

var (
	peerIP     = netip.MustParseAddr("10.0.0.2")
	strangerIP = netip.MustParseAddr("10.0.0.99")
	webGroup   = []string{"web"}
	dbGroup    = []string{"db"}
)

func TestParseRuleDefaults(t *testing.T) {
	r, err := firewall.ParseRule(config.FirewallRule{})
	if err != nil {
		t.Fatalf("ParseRule empty: %v", err)
	}
	if !r.PortAny {
		t.Error("empty Port should be PortAny")
	}
	if r.Proto != firewall.ProtoAny {
		t.Errorf("empty Proto = %v, want ProtoAny", r.Proto)
	}
	if !r.GroupAny {
		t.Error("empty Group should be GroupAny")
	}
	if !r.CIDAny {
		t.Error("empty CIDR should be CIDAny")
	}
}

func TestParseRuleExplicitFields(t *testing.T) {
	r, err := firewall.ParseRule(config.FirewallRule{
		Port:  "443",
		Proto: "tcp",
		Group: "ops",
		CIDR:  "10.0.0.0/8",
	})
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if r.Port != 443 {
		t.Errorf("Port = %d, want 443", r.Port)
	}
	if r.Proto != firewall.ProtoTCP {
		t.Errorf("Proto = %v, want TCP", r.Proto)
	}
	if r.Group != "ops" {
		t.Errorf("Group = %q, want ops", r.Group)
	}
	if r.CIDAny {
		t.Error("CIDR should not be wildcard")
	}
}

func TestParseRuleBadProto(t *testing.T) {
	if _, err := firewall.ParseRule(config.FirewallRule{Proto: "sctp"}); err == nil {
		t.Error("expected error for unknown protocol")
	}
}

func TestParseRuleBadPort(t *testing.T) {
	if _, err := firewall.ParseRule(config.FirewallRule{Port: "notaport"}); err == nil {
		t.Error("expected error for invalid port")
	}
}

func TestParseRuleBadCIDR(t *testing.T) {
	if _, err := firewall.ParseRule(config.FirewallRule{CIDR: "notacidr"}); err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestAllowMatchingGroup(t *testing.T) {
	fw := firewall.New([]firewall.Rule{
		parseRule(t, "80", "tcp", "web", "any"),
	}, nil)
	if !fw.AllowInbound(peerIP, webGroup, 80, firewall.ProtoTCP) {
		t.Error("group 'web' on port 80 should be allowed")
	}
}

func TestDenyNonMatchingGroup(t *testing.T) {
	fw := firewall.New([]firewall.Rule{
		parseRule(t, "80", "tcp", "web", "any"),
	}, nil)
	if fw.AllowInbound(peerIP, dbGroup, 80, firewall.ProtoTCP) {
		t.Error("group 'db' should be denied (rule requires 'web')")
	}
}

func TestDenyWrongPort(t *testing.T) {
	fw := firewall.New([]firewall.Rule{parseRule(t, "80", "tcp", "any", "any")}, nil)
	if fw.AllowInbound(peerIP, webGroup, 443, firewall.ProtoTCP) {
		t.Error("port 443 should be denied (rule allows only 80)")
	}
}

func TestDenyWrongProto(t *testing.T) {
	fw := firewall.New([]firewall.Rule{parseRule(t, "80", "tcp", "any", "any")}, nil)
	if fw.AllowInbound(peerIP, webGroup, 80, firewall.ProtoUDP) {
		t.Error("UDP should be denied (rule requires TCP)")
	}
}

func TestWildcardRuleAllowsAll(t *testing.T) {
	fw := firewall.New([]firewall.Rule{parseRule(t, "any", "any", "any", "any")}, nil)
	if !fw.AllowInbound(strangerIP, nil, 9999, firewall.ProtoUDP) {
		t.Error("wildcard rule should allow all traffic")
	}
}

func TestCIDRMatchAndMiss(t *testing.T) {
	fw := firewall.New([]firewall.Rule{parseRule(t, "any", "any", "any", "10.0.0.0/24")}, nil)
	if !fw.AllowInbound(netip.MustParseAddr("10.0.0.5"), nil, 22, firewall.ProtoTCP) {
		t.Error("IP inside CIDR should be allowed")
	}
	if fw.AllowInbound(netip.MustParseAddr("192.168.1.1"), nil, 22, firewall.ProtoTCP) {
		t.Error("IP outside CIDR should be denied")
	}
}

func TestNoRulesDeniesAll(t *testing.T) {
	fw := firewall.New(nil, nil)
	if fw.AllowInbound(peerIP, webGroup, 80, firewall.ProtoTCP) {
		t.Error("no rules: inbound should be denied")
	}
	if fw.AllowOutbound(peerIP, webGroup, 80, firewall.ProtoTCP) {
		t.Error("no rules: outbound should be denied")
	}
}

func TestEstablishedReverseDirection(t *testing.T) {
	fw := firewall.New(
		nil, // no inbound rules
		[]firewall.Rule{parseRule(t, "80", "tcp", "any", "any")},
	)

	if !fw.AllowOutbound(peerIP, webGroup, 80, firewall.ProtoTCP) {
		t.Fatal("outbound to port 80 should be allowed by rule")
	}

	if !fw.AllowInbound(peerIP, webGroup, 80, firewall.ProtoTCP) {
		t.Error("inbound reply should be allowed by conntrack (established)")
	}

	if fw.AllowInbound(strangerIP, nil, 80, firewall.ProtoTCP) {
		t.Error("inbound from untracked peer must be denied (no rule, no conntrack)")
	}
}

func TestOutboundAllowedByConntrack(t *testing.T) {
	fw := firewall.New(nil, []firewall.Rule{parseRule(t, "80", "tcp", "any", "any")})

	if !fw.AllowOutbound(peerIP, nil, 80, firewall.ProtoTCP) {
		t.Fatal("first outbound should be allowed by rule")
	}
	if !fw.AllowOutbound(peerIP, nil, 80, firewall.ProtoTCP) {
		t.Error("subsequent outbound should be allowed by conntrack")
	}
}

func TestConntrackExpiry(t *testing.T) {
	fw := firewall.New(
		nil, // no inbound rules
		[]firewall.Rule{parseRule(t, "53", "udp", "any", "any")},
	)

	if !fw.AllowOutbound(peerIP, nil, 53, firewall.ProtoUDP) {
		t.Fatal("outbound should be allowed by rule")
	}
	if !fw.AllowInbound(peerIP, nil, 53, firewall.ProtoUDP) {
		t.Fatal("inbound should be allowed by conntrack before expiry")
	}

	// every UDP entry is immediately stale.
	fw.ExpireWith(time.Hour, time.Nanosecond, time.Hour)

	// deny
	if fw.AllowInbound(peerIP, nil, 53, firewall.ProtoUDP) {
		t.Error("inbound should be denied after conntrack entry expires")
	}
}
