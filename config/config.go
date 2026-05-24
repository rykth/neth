package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration structure.
type Config struct {
	PKI           PKIConfig           `yaml:"pki"`
	Listen        ListenConfig        `yaml:"listen"`
	TUN           TUNConfig           `yaml:"tun"`
	Lighthouse    LighthouseConfig    `yaml:"lighthouse"`
	StaticHostMap map[string][]string `yaml:"static_host_map"`
	Punchy        PunchyConfig        `yaml:"punchy"`
	Firewall      FirewallConfig      `yaml:"firewall"`
	Logging       LoggingConfig       `yaml:"logging"`
}

// PKIConfig holds file paths for the CA certificate, node certificate, and
// node private key.
type PKIConfig struct {
	CA   string `yaml:"ca"`
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// ListenConfig controls the UDP socket the daemon binds to.
type ListenConfig struct {
	Host string `yaml:"host"` // defaults to "0.0.0.0".
	Port int    `yaml:"port"` // required, must be in [1, 65535].
}

// TUNConfig controls the TUN interface.
type TUNConfig struct {
	Dev string `yaml:"dev"` // interface name; defaults to "neth0".
	MTU int    `yaml:"mtu"` // defaults to 1300.
}

// LighthouseConfig controls peer-discovery behaviour.
type LighthouseConfig struct {
	AmLighthouse bool     `yaml:"am_lighthouse"`
	Interval     int      `yaml:"interval"` // defaults to 60.
	Hosts        []string `yaml:"hosts"`    // VPN IPs of designated lighthouse nodes
}

// PunchyConfig enables UDP hole-punching.
type PunchyConfig struct {
	Punch   bool `yaml:"punch"`
	Respond bool `yaml:"respond"`
}

// FirewallConfig holds ordered lists of inbound and outbound rules.
type FirewallConfig struct {
	Inbound  []FirewallRule `yaml:"inbound"`
	Outbound []FirewallRule `yaml:"outbound"`
}

// FirewallRule is a single firewall rule entry as written in config.yaml
type FirewallRule struct {
	Port  string `yaml:"port"`  // "any" or a decimal port number (0–65535)
	Proto string `yaml:"proto"` // "any", "tcp", "udp", or "icmp"
	Group string `yaml:"group"` // group name, or "" / "any" to match all groups
	CIDR  string `yaml:"cidr"`  // CIDR notation, or "" / "any" to match all IPs
}

// LoggingConfig controls the logger.
type LoggingConfig struct {
	Level  string `yaml:"level"`  // "debug", "info", "warn", "error"; defaults to "info"
	Format string `yaml:"format"` //  "text" or "json"; defaults to "text"
}

// Load reads the YAML file at path, applies defaults, and validates the result
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %q: %w", path, err)
	}

	cfg.setDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) setDefaults() {
	if c.Listen.Host == "" {
		c.Listen.Host = "0.0.0.0"
	}
	if c.TUN.Dev == "" {
		c.TUN.Dev = "neth0"
	}
	if c.TUN.MTU == 0 {
		c.TUN.MTU = 1300
	}
	if c.Lighthouse.Interval == 0 {
		c.Lighthouse.Interval = 60
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "text"
	}
}

// Validate checks that all required fields are present and values are in range.
func (c *Config) Validate() error {
	var errs []error

	if c.PKI.CA == "" {
		errs = append(errs, errors.New("pki.ca is required"))
	}
	if c.PKI.Cert == "" {
		errs = append(errs, errors.New("pki.cert is required"))
	}
	if c.PKI.Key == "" {
		errs = append(errs, errors.New("pki.key is required"))
	}
	if c.Listen.Port < 1 || c.Listen.Port > 65535 {
		errs = append(errs, fmt.Errorf("listen.port %d is out of range [1, 65535]", c.Listen.Port))
	}

	return errors.Join(errs...)
}
