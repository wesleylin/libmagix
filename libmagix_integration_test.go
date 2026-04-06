package libmagix_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/wesleylin/libmagix"
)

func TestGIFIdentification(t *testing.T) {
	// 1. Setup a logger that only shows errors unless we run with -v
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// 2. Initialize the engine using the public API
	// This points to our tiny test magic file
	engine, err := libmagix.New("magic/Magdir/basicGif", logger)
	if err != nil {
		t.Fatalf("Failed to initialize engine: %v", err)
	}

	// 3. Load the actual GIF bytes from testdata
	gifData, err := os.ReadFile("testdata/sample.gif")
	if err != nil {
		t.Fatalf("Failed to read test GIF: %v", err)
	}

	// 4. Run the identification
	got := engine.Identify(gifData)
	want := "GIF image data (89a)"

	// 5. Assert
	if got.Message != want {
		t.Errorf("Identify() = %q; want %q", got, want)
	}
}

func TestJavaIdentification(t *testing.T) {
	// 1. Initialize engine
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/java", logger)
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	// 2. Create fake Java class data (Cafe Babe)
	// 0xCAFEBABE = 3405691582
	javaData := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34}

	// 3. Identify
	got := engine.Identify(javaData)
	want := "Java class data"

	if got == nil {
		t.Fatal("Expected identification, got nil")
	}
	if got.Message != want {
		t.Errorf("Got %q, want %q", got.Message, want)
	}
}

func TestHighVersionIdentification(t *testing.T) {
	// 1. Setup Logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// 2. Create a temporary directory for this specific test
	tmpDir := t.TempDir()
	magicFilePath := filepath.Join(tmpDir, "version_check")

	// 3. Write the specific magic rule we want to test
	//    Rule: First byte must be greater than 10
	magicContent := "0\tbyte\t>10\tHigh Version Format\n"
	if err := os.WriteFile(magicFilePath, []byte(magicContent), 0644); err != nil {
		t.Fatalf("Failed to write mock magic file: %v", err)
	}

	// 4. Initialize the engine pointing to our temp file
	engine, err := libmagix.New(magicFilePath, logger)
	if err != nil {
		t.Fatalf("Failed to initialize engine: %v", err)
	}

	// 5. Test Case A: Should Match (Value 11 > 10)
	dataMatch := []byte{11, 0x00, 0x00}
	got := engine.Identify(dataMatch)
	want := "High Version Format"

	if got == nil {
		t.Fatal("Expected match for byte > 10, got nil")
	}
	if got.Message != want {
		t.Errorf("Identify() = %q; want %q", got.Message, want)
	}

	// 6. Test Case B: Should NOT Match (Value 10 is not > 10)
	dataNoMatch := []byte{10, 0x00, 0x00}
	gotNoMatch := engine.Identify(dataNoMatch)

	if gotNoMatch != nil {
		t.Errorf("Expected nil match for value 10, got %q", gotNoMatch.Message)
	}
}

func TestELFIdentification(t *testing.T) {
	// 1. Initialize engine
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/elf", logger)
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	// 2. Load the actual ELF bytes from testdata
	elfData, err := os.ReadFile("testdata/sample.elf")
	if err != nil {
		t.Fatalf("Failed to read test ELF: %v", err)
	}

	// 3. Identify
	got := engine.Identify(elfData)
	want := "64-bit ELF executable"

	if got == nil {
		t.Fatal("Expected identification, got nil")
	}
	if got.Message != want {
		t.Errorf("Got %q, want %q", got.Message, want)
	}
}

func TestELFFromFileIdentification(t *testing.T) {
	// 1. Initialize engine
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/elf", logger)
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	elfData, err := os.ReadFile("testdata/sample.gif")
	if err != nil {
		t.Fatalf("Failed to read test ELF: %v", err)
	}

	// 3. Identify
	got := engine.Identify(elfData)
	want := "64-bit ELF executable"

	if got == nil {
		t.Fatal("Expected identification, got nil")
	}
	if got.Message != want {
		t.Errorf("Got %q, want %q", got.Message, want)
	}
}
