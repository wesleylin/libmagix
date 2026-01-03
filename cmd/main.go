package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/wesleylin/libmagix"
)

func main() {

	// 1. Point to your Magdir folder
	m, err := libmagix.New("./magic/Magdir", slog.Default())
	if err != nil {
		fmt.Printf("Error loading magic files: %v\n", err)
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage: magix <file>")
		return
	}
	// 2. Read file
	filePath := os.Args[1]
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
