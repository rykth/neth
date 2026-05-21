package firewall

import (
	"context"
	"time"
)

const (
	defaultTCPTimeout  = 5 * time.Minute
	defaultUDPTimeout  = 30 * time.Second
	defaultICMPTimeout = 10 * time.Second
)

func (f *Firewall) RunExpiry(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.ct.Expire(defaultTCPTimeout, defaultUDPTimeout, defaultICMPTimeout)
		}
	}
}

// ExpireWith calls conntrack.Expire with caller-supplied timeouts.
func (f *Firewall) ExpireWith(tcpTimeout, udpTimeout, defaultTimeout time.Duration) {
	f.ct.Expire(tcpTimeout, udpTimeout, defaultTimeout)
}
