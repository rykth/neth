package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rykth/neth/config"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "neth-config-*.yaml")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	f.Close()
	return f.Name()
}

const fullConfig = `
pki:
  ca: /etc/neth/ca.crt
  cert: /etc/neth/node.crt
  key: /etc/neth/node.key

listen:
  host: 0.0.0.0
  port: 4242

tun:
  dev: neth0
  mtu: 1300

lighthouse:
  am_lighthouse: false
  interval: 30
  hosts:
    - "10.0.0.1"

static_host_map:
  "10.0.0.1": ["203.0.113.1:4242"]

punchy:
  punch: true
  respond: true

firewall:
  inbound:
    - port: any
      proto: any
      group: servers
  outbound:
    - port: "443"
      proto: tcp
      cidr: "0.0.0.0/0"

logging:
  level: debug
  format: json
`

func TestLoadFullConfig(t *testing.T) {
	path := writeTemp(t, fullConfig)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.PKI.CA != "/etc/neth/ca.crt" {
		t.Errorf("PKI.CA = %q", cfg.PKI.CA)
	}
	if cfg.PKI.Cert != "/etc/neth/node.crt" {
		t.Errorf("PKI.Cert = %q", cfg.PKI.Cert)
	}
	if cfg.PKI.Key != "/etc/neth/node.key" {
		t.Errorf("PKI.Key = %q", cfg.PKI.Key)
	}

	if cfg.Listen.Host != "0.0.0.0" {
		t.Errorf("Listen.Host = %q", cfg.Listen.Host)
	}
	if cfg.Listen.Port != 4242 {
		t.Errorf("Listen.Port = %d", cfg.Listen.Port)
	}

	if cfg.TUN.Dev != "neth0" {
		t.Errorf("TUN.Dev = %q", cfg.TUN.Dev)
	}
	if cfg.TUN.MTU != 1300 {
		t.Errorf("TUN.MTU = %d", cfg.TUN.MTU)
	}

	if cfg.Lighthouse.AmLighthouse {
		t.Error("Lighthouse.AmLighthouse should be false")
	}
	if cfg.Lighthouse.Interval != 30 {
		t.Errorf("Lighthouse.Interval = %d", cfg.Lighthouse.Interval)
	}
	if len(cfg.Lighthouse.Hosts) != 1 || cfg.Lighthouse.Hosts[0] != "10.0.0.1" {
		t.Errorf("Lighthouse.Hosts = %v", cfg.Lighthouse.Hosts)
	}

	addrs, ok := cfg.StaticHostMap["10.0.0.1"]
	if !ok || len(addrs) != 1 || addrs[0] != "203.0.113.1:4242" {
		t.Errorf("StaticHostMap = %v", cfg.StaticHostMap)
	}

	if !cfg.Punchy.Punch {
		t.Error("Punchy.Punch should be true")
	}
	if !cfg.Punchy.Respond {
		t.Error("Punchy.Respond should be true")
	}

	if len(cfg.Firewall.Inbound) != 1 {
		t.Fatalf("Firewall.Inbound count = %d", len(cfg.Firewall.Inbound))
	}
	if cfg.Firewall.Inbound[0].Proto != "any" {
		t.Errorf("Firewall.Inbound[0].Proto = %q", cfg.Firewall.Inbound[0].Proto)
	}
	if cfg.Firewall.Inbound[0].Group != "servers" {
		t.Errorf("Firewall.Inbound[0].Group = %q", cfg.Firewall.Inbound[0].Group)
	}
	if len(cfg.Firewall.Outbound) != 1 {
		t.Fatalf("Firewall.Outbound count = %d", len(cfg.Firewall.Outbound))
	}
	if cfg.Firewall.Outbound[0].Port != "443" {
		t.Errorf("Firewall.Outbound[0].Port = %q", cfg.Firewall.Outbound[0].Port)
	}

	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Logging.Format = %q", cfg.Logging.Format)
	}
}

func TestLoadDefaults(t *testing.T) {
	minimal := `
pki:
  ca: ca.crt
  cert: node.crt
  key: node.key
listen:
  port: 4242
`
	path := writeTemp(t, minimal)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen.Host != "0.0.0.0" {
		t.Errorf("default Listen.Host = %q, want 0.0.0.0", cfg.Listen.Host)
	}
	if cfg.TUN.Dev != "neth0" {
		t.Errorf("default TUN.Dev = %q, want neth0", cfg.TUN.Dev)
	}
	if cfg.TUN.MTU != 1300 {
		t.Errorf("default TUN.MTU = %d, want 1300", cfg.TUN.MTU)
	}
	if cfg.Lighthouse.Interval != 60 {
		t.Errorf("default Lighthouse.Interval = %d, want 60", cfg.Lighthouse.Interval)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("default Logging.Level = %q, want info", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Errorf("default Logging.Format = %q, want text", cfg.Logging.Format)
	}
}

func TestValidateMissingPKI(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "missing ca",
			content: `
pki:
  cert: node.crt
  key: node.key
listen:
  port: 4242
`,
			wantErr: "pki.ca is required",
		},
		{
			name: "missing cert",
			content: `
pki:
  ca: ca.crt
  key: node.key
listen:
  port: 4242
`,
			wantErr: "pki.cert is required",
		},
		{
			name: "missing key",
			content: `
pki:
  ca: ca.crt
  cert: node.crt
listen:
  port: 4242
`,
			wantErr: "pki.key is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, tc.content)
			_, err := config.Load(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tc.wantErr {
				t.Errorf("error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidatePortRange(t *testing.T) {
	cases := []struct {
		name string
		port int
		ok   bool
	}{
		{"zero", 0, false},
		{"negative via yaml not possible but validate", -1, false},
		{"too large", 65536, false},
		{"min valid", 1, true},
		{"max valid", 65535, true},
		{"typical", 4242, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				PKI:    config.PKIConfig{CA: "ca.crt", Cert: "node.crt", Key: "node.key"},
				Listen: config.ListenConfig{Port: tc.port},
			}
			err := cfg.Validate()
			if tc.ok && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("expected error for port", tc.port)
			}
		})
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	cfg := &config.Config{}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected errors for empty config")
	}

	msg := err.Error()
	for _, want := range []string{"pki.ca", "pki.cert", "pki.key", "listen.port"} {
		found := false
		for i := range msg {
			if i+len(want) <= len(msg) && msg[i:i+len(want)] == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("error message missing %q: %s", want, msg)
		}
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	path := writeTemp(t, ":\nnot: valid: yaml: here\n")
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected parse error for invalid YAML")
	}
}
