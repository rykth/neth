//go:build linux

package neth

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	noise "github.com/flynn/noise"

	"github.com/rykth/neth/cert"
	"github.com/rykth/neth/config"
	"github.com/rykth/neth/firewall"
	"github.com/rykth/neth/header"
	"github.com/rykth/neth/nethpb"
	"github.com/rykth/neth/noiseutil"
	"github.com/rykth/neth/tun"
	"github.com/rykth/neth/udp"
)

const (
	tunReadBufSize = 65535
	udpReadBufSize = 65535
)

// Interface is the central orchestrator: it reads plaintext packets from the
// TUN device, encrypts and forwards them over UDP, and reverses that path for
// inbound packets.
type Interface struct {
	cfg          *config.Config
	pki          *PKI
	tunDev       *tun.Device
	udpConn      *udp.Conn
	hostmap      *HostMap
	handshakeMgr *HandshakeManager
	fw           *firewall.Firewall
	lighthouse   *LightHouse
	punchy       *Punchy

	peerCertsMu sync.RWMutex
	peerCerts   map[netip.Addr]*cert.Certificate
}

// NewInterface constructs and wires all subsystems from cfg
func NewInterface(cfg *config.Config) (*Interface, error) {
	pki, err := LoadPKI(cfg.PKI)
	if err != nil {
		return nil, err
	}

	fw, err := buildFirewall(cfg.Firewall)
	if err != nil {
		return nil, fmt.Errorf("interface: firewall: %w", err)
	}

	conn, err := udp.Listen(cfg.Listen.Host, cfg.Listen.Port)
	if err != nil {
		return nil, fmt.Errorf("interface: udp: %w", err)
	}

	tunDev, err := tun.Open(cfg.TUN.Dev, pki.NodeCert.VpnIP.String(), cfg.TUN.MTU)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("interface: tun: %w", err)
	}

	lh, err := buildLightHouse(cfg, conn)
	if err != nil {
		_ = conn.Close()
		_ = tunDev.Close()
		return nil, fmt.Errorf("interface: lighthouse: %w", err)
	}

	iface := &Interface{
		cfg:        cfg,
		pki:        pki,
		tunDev:     tunDev,
		udpConn:    conn,
		hostmap:    NewHostMap(),
		fw:         fw,
		lighthouse: lh,
		peerCerts:  make(map[netip.Addr]*cert.Certificate),
	}

	if cfg.Punchy.Punch || cfg.Punchy.Respond {
		p := NewPunchy(cfg.Punchy.Punch, cfg.Punchy.Respond, conn)
		iface.punchy = p
		lh.SetPunchy(p)
	}

	staticKey := noise.DHKey{
		Private: pki.Curve25519Key,
		Public:  pki.NodeCert.X25519PublicKey,
	}
	iface.handshakeMgr = NewHandshakeManager(
		pki.NodeCert,
		staticKey,
		pki.CACerts,
		conn,
		iface.onHandshakeComplete,
	)

	return iface, nil
}

// Run starts all background goroutines and blocks until ctx is cancelled
func (iface *Interface) Run(ctx context.Context) {
	interval := time.Duration(iface.cfg.Lighthouse.Interval) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}

	go iface.handshakeMgr.Run(ctx)
	go iface.lighthouse.Run(ctx, interval, iface.lighthouseSendFn)
	go iface.fw.RunExpiry(ctx, 30*time.Second)
	go iface.readFromTUN(ctx)
	go iface.readFromUDP(ctx)

	<-ctx.Done()
	_ = iface.tunDev.Close()
	_ = iface.udpConn.Close()
}

func (iface *Interface) readFromTUN(ctx context.Context) {
	buf := make([]byte, tunReadBufSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := iface.tunDev.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("tun read error", "err", err)
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		iface.consumeInsidePacket(pkt)
	}
}

func (iface *Interface) readFromUDP(ctx context.Context) {
	buf := make([]byte, udpReadBufSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, from, err := iface.udpConn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("udp read error", "err", err)
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		iface.consumeOutsidePacket(pkt, from)
	}
}

func (iface *Interface) consumeInsidePacket(pkt []byte) {
	dstIP, ok := dstIPFromIPv4(pkt)
	if !ok {
		return
	}

	host := iface.hostmap.GetByVpnIP(dstIP)

	var dstGroups []string
	if host != nil && host.Cert != nil {
		dstGroups = host.Cert.Groups
	}

	proto := protoFromIPv4(pkt)
	dstPort := dstPortFromIPv4(pkt)

	if !iface.fw.AllowOutbound(dstIP, dstGroups, dstPort, proto) {
		slog.Debug("outbound blocked by firewall", "dst", dstIP, "port", dstPort)
		return
	}

	if host != nil {
		iface.sendToRemote(host, pkt)
		return
	}

	remoteCert := iface.getPeerCert(dstIP)
	if remoteCert == nil {
		iface.handshakeMgr.QueuePacket(dstIP, pkt)
		return
	}

	remoteAddrs := iface.lighthouse.GetAddrs(dstIP)
	if len(remoteAddrs) == 0 {
		iface.lighthouse.QueryPeer(dstIP, iface.lighthouseSendFn)
		iface.handshakeMgr.QueuePacket(dstIP, pkt)
		return
	}

	if err := iface.handshakeMgr.StartHandshake(dstIP, &remoteAddrs[0], remoteCert); err != nil {
		slog.Warn("start handshake failed", "peer", dstIP, "err", err)
		return
	}
	iface.handshakeMgr.QueuePacket(dstIP, pkt)
}

func (iface *Interface) consumeOutsidePacket(pkt []byte, from *net.UDPAddr) {
	if len(pkt) < header.HeaderLen {
		return
	}
	hdr, err := header.Parse(pkt)
	if err != nil {
		return
	}

	switch hdr.Type {
	case header.TypeMessage:
		iface.handleMessage(pkt, hdr, from)
	case header.TypeHandshake:
		iface.handleHandshake(pkt, hdr, from)
	case header.TypeLightHouse:
		iface.handleLightHouse(pkt, hdr, from)
	case header.TypeTest:
		iface.handleTest(from)
	case header.TypeCloseTunnel:
		iface.handleCloseTunnel(hdr)
	}
}

func (iface *Interface) handleMessage(pkt []byte, hdr *header.Header, from *net.UDPAddr) {
	host := iface.hostmap.GetByIndex(hdr.RemoteIndex)
	if host == nil {
		if iface.punchy != nil {
			iface.punchy.RespondToPunch(from)
		}
		return
	}

	if host.CheckReplay(hdr.MessageCounter) {
		slog.Debug("replay detected", "peer", host.VpnIP, "counter", hdr.MessageCounter)
		return
	}

	plaintext, err := noiseutil.Decrypt(host.RecvCipher, hdr.MessageCounter, pkt[:header.HeaderLen], pkt[header.HeaderLen:])
	if err != nil {
		slog.Warn("decrypt failed", "peer", host.VpnIP, "err", err)
		return
	}

	srcIP, ok := srcIPFromIPv4(plaintext)
	if !ok {
		return
	}

	var srcGroups []string
	if host.Cert != nil {
		srcGroups = host.Cert.Groups
	}
	inProto := protoFromIPv4(plaintext)
	dstPort := dstPortFromIPv4(plaintext)

	if !iface.fw.AllowInbound(srcIP, srcGroups, dstPort, inProto) {
		slog.Debug("inbound blocked by firewall", "src", srcIP, "port", dstPort)
		return
	}

	if _, err := iface.tunDev.Write(plaintext); err != nil {
		slog.Warn("tun write failed", "err", err)
	}
}

func (iface *Interface) handleHandshake(pkt []byte, hdr *header.Header, from *net.UDPAddr) {
	switch header.HandshakeSubType(hdr.SubType) {
	case header.HandshakeInitiation:
		if err := iface.handshakeMgr.HandleStage0(pkt, from); err != nil {
			slog.Warn("handshake stage0 failed", "from", from, "err", err)
		}
	case header.HandshakeResponse:
		if err := iface.handshakeMgr.HandleStage1(pkt); err != nil {
			slog.Warn("handshake stage1 failed", "from", from, "err", err)
		}
	}
}

func (iface *Interface) handleLightHouse(pkt []byte, hdr *header.Header, from *net.UDPAddr) {
	var senderVPN netip.Addr
	if host := iface.hostmap.GetByIndex(hdr.RemoteIndex); host != nil {
		senderVPN = host.VpnIP
	} else if vpnIP, ok := iface.lighthouse.VpnIPByAddr(*from); ok {
		senderVPN = vpnIP
	} else {
		return
	}

	var msg nethpb.LightHouseMessage
	if err := proto.Unmarshal(pkt[header.HeaderLen:], &msg); err != nil {
		slog.Warn("lighthouse unmarshal failed", "err", err)
		return
	}
	iface.lighthouse.HandleMessage(&msg, senderVPN, iface.lighthouseSendFn)
}

func (iface *Interface) handleTest(from *net.UDPAddr) {
	hdr := header.Header{Version: header.Version, Type: header.TypeTest}
	b := hdr.Bytes()
	_, _ = iface.udpConn.WriteTo(b[:], from)
}

func (iface *Interface) handleCloseTunnel(hdr *header.Header) {
	if host := iface.hostmap.GetByIndex(hdr.RemoteIndex); host != nil {
		iface.hostmap.Remove(host.VpnIP)
	}
}

func (iface *Interface) sendToRemote(host *HostInfo, plaintext []byte) {
	counter := host.Counter.Add(1)
	hdr := header.Header{
		Version:        header.Version,
		Type:           header.TypeMessage,
		RemoteIndex:    host.RemoteIndex,
		MessageCounter: counter,
	}
	hdrBytes := hdr.Bytes()

	ct, err := noiseutil.Encrypt(host.SendCipher, counter, hdrBytes[:], plaintext)
	if err != nil {
		slog.Error("encrypt failed", "peer", host.VpnIP, "err", err)
		return
	}

	wire := make([]byte, header.HeaderLen+len(ct))
	copy(wire, hdrBytes[:])
	copy(wire[header.HeaderLen:], ct)

	if _, err := iface.udpConn.WriteTo(wire, host.Remote); err != nil {
		slog.Warn("send to remote failed", "peer", host.VpnIP, "err", err)
	}
}

// lighthouseSendFn is the sendFn injected into LightHouse
func (iface *Interface) lighthouseSendFn(data []byte, to *net.UDPAddr) {
	if _, err := iface.udpConn.WriteTo(data, to); err != nil {
		slog.Warn("lighthouse send failed", "to", to, "err", err)
	}
}

// onHandshakeComplete is called by HandshakeManager when a Noise session is
// established
func (iface *Interface) onHandshakeComplete(h *HostInfo, pending [][]byte) {
	iface.hostmap.Add(h)
	if h.Cert != nil {
		iface.peerCertsMu.Lock()
		iface.peerCerts[h.VpnIP] = h.Cert
		iface.peerCertsMu.Unlock()
	}
	slog.Info("session established", "peer", h.VpnIP, "remote", h.Remote)
	for _, pkt := range pending {
		iface.sendToRemote(h, pkt)
	}
}

// getPeerCert returns a cached peer certificate, or nil if not yet known
func (iface *Interface) getPeerCert(vpnIP netip.Addr) *cert.Certificate {
	iface.peerCertsMu.RLock()
	defer iface.peerCertsMu.RUnlock()
	return iface.peerCerts[vpnIP]
}

// AddPeerCert pre-seeds the peer certificate cache so that this node can
// initiate outbound Noise handshakes to vpnIP without waiting for the remote
// peer to connect first
func (iface *Interface) AddPeerCert(vpnIP netip.Addr, c *cert.Certificate) {
	iface.peerCertsMu.Lock()
	iface.peerCerts[vpnIP] = c
	iface.peerCertsMu.Unlock()
}

func buildFirewall(cfg config.FirewallConfig) (*firewall.Firewall, error) {
	inbound := make([]firewall.Rule, 0, len(cfg.Inbound))
	for i, r := range cfg.Inbound {
		rule, err := firewall.ParseRule(r)
		if err != nil {
			return nil, fmt.Errorf("inbound rule %d: %w", i, err)
		}
		inbound = append(inbound, rule)
	}
	outbound := make([]firewall.Rule, 0, len(cfg.Outbound))
	for i, r := range cfg.Outbound {
		rule, err := firewall.ParseRule(r)
		if err != nil {
			return nil, fmt.Errorf("outbound rule %d: %w", i, err)
		}
		outbound = append(outbound, rule)
	}
	return firewall.New(inbound, outbound), nil
}

func buildLightHouse(cfg *config.Config, conn *udp.Conn) (*LightHouse, error) {
	var lhIPs []netip.Addr
	for _, host := range cfg.Lighthouse.Hosts {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, fmt.Errorf("lighthouse host %q: %w", host, err)
		}
		lhIPs = append(lhIPs, ip)
	}

	myAddrs := localUDPAddrs(conn.LocalAddr().Port)

	lh := NewLightHouse(cfg.Lighthouse.AmLighthouse, lhIPs, myAddrs)

	for vpnIPStr, addrStrs := range cfg.StaticHostMap {
		vpnIP, err := netip.ParseAddr(vpnIPStr)
		if err != nil {
			return nil, fmt.Errorf("static_host_map key %q: %w", vpnIPStr, err)
		}
		for _, addrStr := range addrStrs {
			udpAddr, err := net.ResolveUDPAddr("udp4", addrStr)
			if err != nil {
				return nil, fmt.Errorf("static_host_map %q addr %q: %w", vpnIPStr, addrStr, err)
			}
			lh.AddStaticEntry(vpnIP, *udpAddr)
		}
	}

	return lh, nil
}

// localUDPAddrs enumerates all non-loopback IPv4 addresses on the host and
// pairs them with port
func localUDPAddrs(port int) []net.UDPAddr {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.UDPAddr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				out = append(out, net.UDPAddr{IP: ip4, Port: port})
			}
		}
	}
	return out
}

func dstIPFromIPv4(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}), true
}

func srcIPFromIPv4(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}), true
}

func protoFromIPv4(pkt []byte) firewall.Proto {
	if len(pkt) < 10 {
		return firewall.ProtoAny
	}
	return firewall.Proto(pkt[9])
}

func dstPortFromIPv4(pkt []byte) uint16 {
	if len(pkt) < 20 {
		return 0
	}
	ihl := int(pkt[0]&0x0f) * 4
	p := firewall.Proto(pkt[9])
	if (p == firewall.ProtoTCP || p == firewall.ProtoUDP) && len(pkt) >= ihl+4 {
		return binary.BigEndian.Uint16(pkt[ihl+2:])
	}
	return 0
}
