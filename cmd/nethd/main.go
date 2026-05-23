//go:build linux

// nethd is the neth overlay-network daemon.
//
// Usage:
//
//	nethd [-config /etc/neth/config.yaml] [-version]
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/rykth/neth"
	"github.com/rykth/neth/config"
)

const version = "0.1.0"

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("nethd", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/neth/config.yaml", "path to config file")
	showVersion := fs.Bool("version", false, "print version and exit")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Printf("nethd %s\n", version)
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nethd: config: %v\n", err)
		return 1
	}

	logger := buildLogger(cfg.Logging.Level, cfg.Logging.Format)
	slog.SetDefault(logger)

	iface, err := neth.NewInterface(cfg)
	if err != nil {
		slog.Error("failed to start interface", "err", err)
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	slog.Info("nethd started", "version", version, "config", *configPath)

	iface.Run(ctx)

	slog.Info("nethd stopped")
	return 0
}

func buildLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(handler)
}
