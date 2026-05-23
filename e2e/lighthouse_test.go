//go:build linux

package e2e_test

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	neth "github.com/rykth/neth"
	"github.com/rykth/neth/header"
	"github.com/rykth/neth/nethpb"
	"google.golang.org/protobuf/proto"
)

func TestLighthouseDiscovery(t *testing.T) {
	lhVPN := netip.MustParseAddr("10.100.0.1")
	aVPN := netip.MustParseAddr("10.100.0.2")
	bVPN := netip.MustParseAddr("10.100.0.3")

	lhConn := listenUDP(t)
	aConn := listenUDP(t)
	bConn := listenUDP(t)
	t.Cleanup(func() { lhConn.Close(); aConn.Close(); bConn.Close() })

	lhAddr := lhConn.LocalAddr().(*net.UDPAddr)
	aAddr := aConn.LocalAddr().(*net.UDPAddr)
	bAddr := bConn.LocalAddr().(*net.UDPAddr)

	lhNode := neth.NewLightHouse(true, nil, []net.UDPAddr{*lhAddr})
	nodeA := neth.NewLightHouse(false, []netip.Addr{lhVPN}, []net.UDPAddr{*aAddr})
	nodeB := neth.NewLightHouse(false, []netip.Addr{lhVPN}, []net.UDPAddr{*bAddr})

	nodeA.AddStaticEntry(lhVPN, *lhAddr)
	nodeB.AddStaticEntry(lhVPN, *lhAddr)

	lhNode.AddStaticEntry(aVPN, *aAddr)
	lhNode.AddStaticEntry(bVPN, *bAddr)

	addrToVPN := map[string]netip.Addr{
		udpKey(lhAddr): lhVPN,
		udpKey(aAddr):  aVPN,
		udpKey(bAddr):  bVPN,
	}

	lhSend := makeSendFn(lhConn)
	aSend := makeSendFn(aConn)
	bSend := makeSendFn(bConn)

	go routeLighthousePackets(lhConn, lhNode, addrToVPN, lhSend)
	go routeLighthousePackets(aConn, nodeA, addrToVPN, aSend)
	go routeLighthousePackets(bConn, nodeB, addrToVPN, bSend)

	nodeA.Advertise(aSend)
	nodeB.Advertise(bSend)

	time.Sleep(100 * time.Millisecond)

	nodeA.QueryPeer(bVPN, aSend)

	var discovered []net.UDPAddr
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if discovered = nodeA.GetAddrs(bVPN); len(discovered) > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	if len(discovered) == 0 {
		t.Fatal("nodeA did not discover nodeB's address via lighthouse within 3s")
	}
	if discovered[0].Port != bAddr.Port {
		t.Errorf("discovered port %d, want %d", discovered[0].Port, bAddr.Port)
	}
	t.Logf("nodeA discovered nodeB at %s", &discovered[0])
}

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listenUDP: %v", err)
	}
	return conn
}

func makeSendFn(conn *net.UDPConn) func([]byte, *net.UDPAddr) {
	return func(data []byte, to *net.UDPAddr) {
		conn.WriteTo(data, to) //nolint:errcheck
	}
}

func udpKey(a *net.UDPAddr) string {
	return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
}

func routeLighthousePackets(
	conn *net.UDPConn,
	lh *neth.LightHouse,
	addrToVPN map[string]netip.Addr,
	sendFn func([]byte, *net.UDPAddr),
) {
	buf := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // connection closed - test is done
		}
		if n < header.HeaderLen {
			continue
		}
		senderVPN, ok := addrToVPN[udpKey(from)]
		if !ok {
			continue
		}
		var msg nethpb.LightHouseMessage
		if err := proto.Unmarshal(buf[header.HeaderLen:n], &msg); err != nil {
			continue
		}
		lh.HandleMessage(&msg, senderVPN, sendFn)
	}
}
