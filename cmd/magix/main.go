package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/wesleylin/libmagix"
	"github.com/wesleylin/libmagix/magic"
)

func main() {
	verbose := flag.Bool("v", false, "enable debug logging")
	magicPath := flag.String("m", "", "magic file or directory (default: embedded database)")
	mimeOnly := flag.Bool("i", false, "output MIME type strings")
	brief := flag.Bool("b", false, "do not prepend filenames to output")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: magix [-v] [-b] [-i] [-m magic] file...\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	var logger *slog.Logger
	if *verbose {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}

	var (
		m   *libmagix.Magix
		err error
	)
	if *magicPath == "" {
		m, err = libmagix.NewFS(magic.FS, "Magdir", logger)
	} else {
		m, err = libmagix.New(*magicPath, logger)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading magic files: %v\n", err)
		os.Exit(1)
	}

	files := flag.Args()
	if len(files) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	status := 0
	for _, filePath := range files {
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "magix: %s: %v\n", filePath, err)
			status = 1
			continue
		}

		prefix := ""
		if !*brief {
			prefix = filePath + ": "
		}

		result := m.Identify(data)
		switch {
		case *mimeOnly && result != nil && result.Mime != "":
			fmt.Printf("%s%s\n", prefix, result.Mime)
		case *mimeOnly:
			fmt.Printf("%sapplication/octet-stream\n", prefix)
		case result != nil && result.Message != "":
			fmt.Printf("%s%s\n", prefix, result.Message)
		default:
			fmt.Printf("%sdata\n", prefix)
		}
	}
	os.Exit(status)
}
