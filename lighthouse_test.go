package neth_test

import (
	"net"
	"net/netip"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/rykth/neth"
	"github.com/rykth/neth/header"
	"github.com/rykth/neth/nethpb"
)

type captureSend struct {
	addr  *net.UDPAddr
	bytes []byte
	calls int
}

func (c *captureSend) fn(data []byte, addr *net.UDPAddr) {
	c.calls++
	c.addr = addr
	c.bytes = append([]byte(nil), data...)
}

func parseLightHouseReply(t *testing.T, raw []byte) *nethpb.LightHouseMessage {
	t.Helper()
	if len(raw) <= header.HeaderLen {
		t.Fatalf("reply packet too short: %d bytes", len(raw))
	}
	var msg nethpb.LightHouseMessage
	if err := proto.Unmarshal(raw[header.HeaderLen:], &msg); err != nil {
		t.Fatalf("unmarshal LightHouseMessage: %v", err)
	}
	return &msg
}

func TestLightHouseQueryReply(t *testing.T) {
	lh := neth.NewLightHouse(true, nil, nil)

	querierVPN := netip.MustParseAddr("10.0.0.1")
	querierPhys := net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 4242}

	peerVPN := netip.MustParseAddr("10.0.0.2")
	peerPhys := net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 4243}

	lh.AddStaticEntry(querierVPN, querierPhys) // so the reply is routed back
	lh.AddStaticEntry(peerVPN, peerPhys)       // the answer the lighthouse has

	cap := &captureSend{}
	lh.HandleMessage(&nethpb.LightHouseMessage{
		Body: &nethpb.LightHouseMessage_Query{
			Query: &nethpb.HostQuery{VpnIp: peerVPN.String()},
		},
	}, querierVPN, cap.fn)

	if cap.calls == 0 {
		t.Fatal("sendFn was not called")
	}
	if cap.addr.String() != querierPhys.String() {
		t.Errorf("reply sent to %v, want %v", cap.addr, &querierPhys)
	}

	msg := parseLightHouseReply(t, cap.bytes)
	qr := msg.GetQueryReply()
	if qr == nil {
		t.Fatal("expected QueryReply in reply")
	}
	if qr.GetVpnIp() != peerVPN.String() {
		t.Errorf("QueryReply.VpnIp = %q, want %q", qr.GetVpnIp(), peerVPN.String())
	}
	if len(qr.GetAddrs()) != 1 {
		t.Fatalf("QueryReply.Addrs count = %d, want 1", len(qr.GetAddrs()))
	}
	if qr.GetAddrs()[0].GetIp() != "5.6.7.8" {
		t.Errorf("QueryReply addr IP = %q, want 5.6.7.8", qr.GetAddrs()[0].GetIp())
	}
	if qr.GetAddrs()[0].GetPort() != 4243 {
		t.Errorf("QueryReply addr port = %d, want 4243", qr.GetAddrs()[0].GetPort())
	}
}

func TestLightHouseQueryUnknownPeer(t *testing.T) {
	lh := neth.NewLightHouse(true, nil, nil)

	querierVPN := netip.MustParseAddr("10.0.0.1")
	querierPhys := net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 4242}
	lh.AddStaticEntry(querierVPN, querierPhys)

	cap := &captureSend{}
	lh.HandleMessage(&nethpb.LightHouseMessage{
		Body: &nethpb.LightHouseMessage_Query{
			Query: &nethpb.HostQuery{VpnIp: "10.0.0.99"},
		},
	}, querierVPN, cap.fn)

	if cap.calls == 0 {
		t.Fatal("sendFn should be called even for unknown peer")
	}
	msg := parseLightHouseReply(t, cap.bytes)
	qr := msg.GetQueryReply()
	if qr == nil {
		t.Fatal("expected QueryReply")
	}
	if len(qr.GetAddrs()) != 0 {
		t.Errorf("expected empty addr list for unknown peer, got %d", len(qr.GetAddrs()))
	}
}

func TestLightHouseUpdateStoresAddrs(t *testing.T) {
	lh := neth.NewLightHouse(true, nil, nil)

	senderVPN := netip.MustParseAddr("10.0.0.3")
	lh.HandleMessage(&nethpb.LightHouseMessage{
		Body: &nethpb.LightHouseMessage_Update{
			Update: &nethpb.HostUpdateNotification{
				Addrs: []*nethpb.IpPort{
					{Ip: "9.10.11.12", Port: 4242},
					{Ip: "192.168.1.5", Port: 4242},
				},
			},
		},
	}, senderVPN, func([]byte, *net.UDPAddr) {})

	addrs := lh.GetAddrs(senderVPN)
	if len(addrs) != 2 {
		t.Fatalf("stored addr count = %d, want 2", len(addrs))
	}
	if addrs[0].IP.String() != "9.10.11.12" {
		t.Errorf("addr[0] = %v, want 9.10.11.12", addrs[0].IP)
	}
	if addrs[1].IP.String() != "192.168.1.5" {
		t.Errorf("addr[1] = %v, want 192.168.1.5", addrs[1].IP)
	}
}

func TestLightHouseUpdateIgnoredWhenNotLighthouse(t *testing.T) {
	lh := neth.NewLightHouse(false, nil, nil)

	senderVPN := netip.MustParseAddr("10.0.0.4")
	lh.HandleMessage(&nethpb.LightHouseMessage{
		Body: &nethpb.LightHouseMessage_Update{
			Update: &nethpb.HostUpdateNotification{
				Addrs: []*nethpb.IpPort{{Ip: "1.2.3.4", Port: 4242}},
			},
		},
	}, senderVPN, func([]byte, *net.UDPAddr) {})

	if lh.GetAddrs(senderVPN) != nil {
		t.Error("regular node should not store HostUpdateNotification")
	}
}

func TestLightHouseQueryReplyStoresAddrs(t *testing.T) {
	lh := neth.NewLightHouse(false, nil, nil)

	peerVPN := netip.MustParseAddr("10.0.0.5")
	lighthouseVPN := netip.MustParseAddr("10.0.0.254")

	lh.HandleMessage(&nethpb.LightHouseMessage{
		Body: &nethpb.LightHouseMessage_QueryReply{
			QueryReply: &nethpb.HostQueryReply{
				VpnIp: peerVPN.String(),
				Addrs: []*nethpb.IpPort{{Ip: "200.1.2.3", Port: 4242}},
			},
		},
	}, lighthouseVPN, func([]byte, *net.UDPAddr) {})

	addrs := lh.GetAddrs(peerVPN)
	if len(addrs) != 1 || addrs[0].IP.String() != "200.1.2.3" {
		t.Errorf("addrStore after QueryReply: %v, want [{200.1.2.3 4242}]", addrs)
	}
}

func TestLightHouseAdvertise(t *testing.T) {
	myAddr := net.UDPAddr{IP: net.ParseIP("10.1.2.3"), Port: 4242}
	lhVPN := netip.MustParseAddr("10.0.0.254")
	lhPhys := net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 4242}

	lh := neth.NewLightHouse(false, []netip.Addr{lhVPN}, []net.UDPAddr{myAddr})
	lh.AddStaticEntry(lhVPN, lhPhys)

	cap := &captureSend{}
	lh.Advertise(cap.fn)

	if cap.calls == 0 {
		t.Fatal("Advertise did not call sendFn")
	}
	if cap.addr.String() != lhPhys.String() {
		t.Errorf("Advertise sent to %v, want %v", cap.addr, &lhPhys)
	}

	msg := parseLightHouseReply(t, cap.bytes)
	upd := msg.GetUpdate()
	if upd == nil {
		t.Fatal("expected HostUpdateNotification in Advertise packet")
	}
	if len(upd.GetAddrs()) != 1 || upd.GetAddrs()[0].GetIp() != "10.1.2.3" {
		t.Errorf("Advertise addrs = %v, want [{10.1.2.3 4242}]", upd.GetAddrs())
	}
}

func TestLightHouseQueryPeer(t *testing.T) {
	lhVPN := netip.MustParseAddr("10.0.0.254")
	lhPhys := net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 4242}
	targetVPN := netip.MustParseAddr("10.0.0.7")

	lh := neth.NewLightHouse(false, []netip.Addr{lhVPN}, nil)
	lh.AddStaticEntry(lhVPN, lhPhys)

	cap := &captureSend{}
	lh.QueryPeer(targetVPN, cap.fn)

	if cap.calls == 0 {
		t.Fatal("QueryPeer did not call sendFn")
	}
	msg := parseLightHouseReply(t, cap.bytes)
	q := msg.GetQuery()
	if q == nil {
		t.Fatal("expected HostQuery in QueryPeer packet")
	}
	if q.GetVpnIp() != targetVPN.String() {
		t.Errorf("HostQuery.VpnIp = %q, want %q", q.GetVpnIp(), targetVPN.String())
	}
}
