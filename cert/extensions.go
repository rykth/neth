package cert

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net/netip"
)

// vpnIPValue is the ASN.1 structure we encode for the VPN IP extension.
// Storing IP bytes and prefix length separately handles both IPv4 and IPv6.
type vpnIPValue struct {
	IP     []byte
	Prefix int
}

func encodeVpnIP(prefix netip.Prefix) (pkix.Extension, error) {
	addr := prefix.Addr()
	var ip []byte
	if addr.Is4() {
		b := addr.As4()
		ip = b[:]
	} else {
		b := addr.As16()
		ip = b[:]
	}
	val, err := asn1.Marshal(vpnIPValue{IP: ip, Prefix: prefix.Bits()})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encode vpn_ip: %w", err)
	}
	return pkix.Extension{Id: oidVpnIP, Value: val}, nil
}

func decodeVpnIP(ext pkix.Extension) (netip.Prefix, error) {
	var v vpnIPValue
	if _, err := asn1.Unmarshal(ext.Value, &v); err != nil {
		return netip.Prefix{}, fmt.Errorf("decode vpn_ip: %w", err)
	}
	var addr netip.Addr
	switch len(v.IP) {
	case 4:
		addr = netip.AddrFrom4([4]byte(v.IP))
	case 16:
		addr = netip.AddrFrom16([16]byte(v.IP))
	default:
		return netip.Prefix{}, fmt.Errorf("decode vpn_ip: unexpected IP length %d", len(v.IP))
	}
	return netip.PrefixFrom(addr, v.Prefix), nil
}

func encodeGroups(groups []string) (pkix.Extension, error) {
	vals := make([]asn1.RawValue, len(groups))
	for i, g := range groups {
		vals[i] = asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(g)}
	}
	val, err := asn1.Marshal(vals)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encode groups: %w", err)
	}
	return pkix.Extension{Id: oidGroups, Value: val}, nil
}

func decodeGroups(ext pkix.Extension) ([]string, error) {
	var vals []asn1.RawValue
	if _, err := asn1.Unmarshal(ext.Value, &vals); err != nil {
		return nil, fmt.Errorf("decode groups: %w", err)
	}
	groups := make([]string, len(vals))
	for i, v := range vals {
		groups[i] = string(v.Bytes)
	}
	return groups, nil
}

func encodeCurve25519Key(pub []byte) (pkix.Extension, error) {
	if len(pub) != 32 {
		return pkix.Extension{}, fmt.Errorf("encode curve25519_key: expected 32 bytes, got %d", len(pub))
	}
	val, err := asn1.Marshal(pub) // encodes as OCTET STRING
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encode curve25519_key: %w", err)
	}
	return pkix.Extension{Id: oidCurve25519Key, Value: val}, nil
}

func decodeCurve25519Key(ext pkix.Extension) ([]byte, error) {
	var b []byte
	if _, err := asn1.Unmarshal(ext.Value, &b); err != nil {
		return nil, fmt.Errorf("decode curve25519_key: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("decode curve25519_key: expected 32 bytes, got %d", len(b))
	}
	return b, nil
}
