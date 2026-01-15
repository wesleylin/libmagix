package libmagix_test

import (
	"log/slog"
	"os"
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
