package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/wesleylin/libmagix"
)

func main() {

	verbose := flag.Bool("v", false, "enable debug logging")
	flag.Parse()

	var logger *slog.Logger
	if *verbose {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	// 1. Point to your Magdir folder
	m, err := libmagix.New("./magic/Magdir", logger)
	if err != nil {
		fmt.Printf("Error loading magic files: %v\n", err)
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage: magix <file>")
		return
	}
	// 2. Read file
	remainingArgs := flag.Args()

	filePath := remainingArgs[0]
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	// 3. Identify!
	result := m.Identify(data)
	if result != nil {
		fmt.Printf("File Type: %s (MIME: %s)\n", result.Message, result.Mime)
	} else {
		fmt.Println("File type not identified.")
	}
}
