package main

import (
	"flag"
	"fmt"
	"os"

	"dsrlab/internal/token"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "dstoken:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("dstoken", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	path := flags.String("path", "", "directory or file to scan")
	configPath := flags.String("config", "", "path to the shared JSON configuration")
	out := flags.String("out", "", "path of the RAW token report to write")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || *configPath == "" || *out == "" {
		return fmt.Errorf("usage: dstoken --path DIR --config CONFIG --out TOKEN_RAW.json")
	}

	cfg, err := token.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	report, err := token.ScanPath(*path, cfg)
	if err != nil {
		return err
	}
	if err := token.WriteReport(*out, report); err != nil {
		return err
	}
	fmt.Printf("scanned %d files, skipped %d, found %d\n",
		report.ScannedFiles, report.SkippedFiles, len(report.Findings))
	return nil
}
