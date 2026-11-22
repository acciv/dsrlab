package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"dsrlab/internal/mock"
)

type mockFileConfig struct {
	Port int `json:"port"`
	Mock struct {
		Port int `json:"port"`
	} `json:"mock"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "dsmock:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("dsmock", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	portFlag := flags.Int("port", 0, "loopback port (0 = OS-assigned)")
	configPath := flags.String("config", "", "optional shared JSON configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}

	port := *portFlag
	explicitPort := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "port" {
			explicitPort = true
		}
	})
	if !explicitPort && *configPath != "" {
		data, err := os.ReadFile(*configPath)
		if err != nil {
			return fmt.Errorf("read mock config: %w", err)
		}
		var cfg mockFileConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parse mock config: %w", err)
		}
		if cfg.Mock.Port != 0 {
			port = cfg.Mock.Port
		} else if cfg.Port != 0 {
			port = cfg.Port
		}
	}

	server, err := mock.New(mock.Config{Port: port})
	if err != nil {
		return err
	}
	// The port line must be the very first stdout line.
	fmt.Printf("PORT:%d\n", server.Port())

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	served := make(chan error, 1)
	go func() { served <- server.Run() }()

	select {
	case <-signals:
		if err := server.Close(); err != nil {
			return err
		}
		<-served
		return nil
	case err := <-served:
		if err != nil && !errors.Is(err, os.ErrClosed) {
			return err
		}
		return nil
	}
}
